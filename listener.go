package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	byteorder "github.com/moolen/udplb/byteorder"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
)

type ListenerParams struct {
	Port        uint16
	ListenAddr  net.IP
	SniMappings map[string]*net.UDPAddr
	Redirects   *bpf.Table
	SourceNat   *bpf.Table
}

type UDPRedirect struct {
	dstAddr [4]byte
	dstPort [2]byte
	srcAddr [4]byte
	srcPort [2]byte
}

type DtlsConn struct {
	packets    [][]byte
	clientAddr *net.UDPAddr
	dstAddr    *net.UDPAddr
	natConn    *net.UDPConn
	listenAddr *net.UDPAddr
	snatAddr   *net.UDPAddr
	timestamp  int64
}

type Flow struct {
	SrcAddr *net.UDPAddr
	DstAddr *net.UDPAddr
}

type FlowMapper interface {
	FindFlow(srcAddr *net.UDPAddr, srcPackets [][]byte) (*Flow, error)
}

//func SetSocketOptions(network string, address string, c syscall.RawConn) error {
//
//	var fn = func(s uintptr) {
//		var setErr error
//		var getErr error
//		setErr = syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
//		if setErr != nil {
//			log.Fatal(setErr)
//		}
//
//		val, getErr := syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT)
//		if getErr != nil {
//			log.Fatal(getErr)
//		}
//		log.Printf("value of IP_TRANSPARENT option is: %d", int(val))
//	}
//	if err := c.Control(fn); err != nil {
//		return err
//	}
//
//	return nil
//
//}

func SetSocketOptions(network string, address string, c syscall.RawConn) error {

	var fn = func(s uintptr) {
		var setErr error
		var getErr error
		setErr = syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.SO_REUSEADDR, 1)
		if setErr != nil {
			log.Fatal(setErr)
		}

		val, getErr := syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.SO_REUSEADDR)
		if getErr != nil {
			log.Fatal(getErr)
		}
		log.Printf("value of IP_TRANSPARENT option is: %d", int(val))
	}
	if err := c.Control(fn); err != nil {
		return err
	}

	return nil

}
//func sendAllBuffered(dtlsConn *DtlsConn) {
//	lc := net.ListenConfig{Control: SetSocketOptions}
//
//	listener, err := lc.ListenPacket(context.Background(), "udp", dtlsConn.clientAddr.String())
//	if err != nil {
//		log.Fatalf("failed to create listener: %s", err)
//		return
//	}
//	defer listener.Close()
//
//	for _, buf := range dtlsConn.packets {
//		listener.WriteTo(buf, dtlsConn.dstAddr)
//	}
//}

func sendAllBuffered(dtlsConn *DtlsConn) {
	for _, buf := range dtlsConn.packets {
		dtlsConn.natConn.Write(buf)
	}

	dtlsConn.packets = nil
}

func addRedirectsTableEntry(redirects *bpf.Table,
	sourceNat *bpf.Table,
	clientSrcAddr *net.UDPAddr,
	listeningAddr *net.UDPAddr,
	srcNatAddr *net.UDPAddr,
	dstAddr *net.UDPAddr) {

	clientSrcPort := byteorder.Htons(uint16(clientSrcAddr.Port))
	clientSrcIp := byteorder.HtonIP(clientSrcAddr.IP)
	listeningAddrPort := byteorder.Htons(uint16(listeningAddr.Port))
	listeningAddrIp := byteorder.HtonIP(listeningAddr.IP)
	srcNatPort := byteorder.Htons(uint16(srcNatAddr.Port))
	srcNatIp := byteorder.HtonIP(srcNatAddr.IP)
	dstPort := byteorder.Htons(uint16(dstAddr.Port))
	dstIp := byteorder.HtonIP(dstAddr.IP)

	tableKey := UDPRedirect{srcAddr: clientSrcIp,
		srcPort: clientSrcPort,
		dstAddr: listeningAddrIp,
		dstPort: listeningAddrPort}

	dstAddrN := UDPRedirect{dstAddr: dstIp,
		dstPort: dstPort,
		srcAddr: srcNatIp,
		srcPort: srcNatPort}

	err := redirects.SetP(unsafe.Pointer(&tableKey), unsafe.Pointer(&dstAddrN))

	if err != nil {
		log.Debugf("failed to update redirects table (%s -> %s) : %s", clientSrcAddr.String(), dstAddr.String(), err)
	} else {

		log.Debugf("updated redirects table ((%s->%s) ---> (%s->%s))",
			clientSrcAddr.String(), listeningAddr.String(), srcNatAddr.String(), dstAddr.String())
	}

	natTableKey := UDPRedirect{
		srcAddr: srcNatIp,
		srcPort: srcNatPort,
		dstAddr: dstIp,
		dstPort: dstPort,
	}

	natTableEntry := UDPRedirect{
		srcAddr: listeningAddrIp,
		srcPort: listeningAddrPort,
		dstAddr: clientSrcIp,
		dstPort: clientSrcPort,
	}
	err = sourceNat.SetP(unsafe.Pointer(&natTableKey), unsafe.Pointer(&natTableEntry))

	if err != nil {
		log.Debugf("failed to update nat table (%s -> %s) : %s", srcNatAddr.String(), dstAddr.String(), err)
	} else {

		log.Debugf("updated nat table ((%s->%s) ---> (%s->%s))",
			clientSrcAddr.String(), listeningAddr.String(), srcNatAddr.String(), dstAddr.String())
	}
}

func forwardPackets(conn *DtlsConn, redirects *bpf.Table, sourceNat *bpf.Table) {
    soc, err := net.DialUDP("udp", nil, conn.dstAddr)
		if err != nil {
			log.Errorf("failed to open UDP connection to: %s", conn.dstAddr)
	    return
		}
	  log.Debugf("opened socket from: %s to %s", soc.LocalAddr().String(), conn.dstAddr.String())
		conn.natConn = soc
		conn.snatAddr = toUDPAddr(soc.LocalAddr())
	addRedirectsTableEntry(redirects, sourceNat, conn.clientAddr, conn.listenAddr, conn.snatAddr, conn.dstAddr)
	sendAllBuffered(conn)
}

func processPacket(conn *DtlsConn, flowMapper FlowMapper, redirects *bpf.Table, sourceNat *bpf.Table) {
	addr := conn.clientAddr
	packets := conn.packets

	flow, err := flowMapper.FindFlow(addr, packets)
	if err != nil {
		log.Errorf("failed to parse conn: %s", err)
		return
	}

	if flow == nil {
		log.Debugf("flow not found %s", addr.String())
		return
	}

	conn.dstAddr = flow.DstAddr
	go forwardPackets(conn, redirects, sourceNat)
}

func toUDPAddr(addr net.Addr) *net.UDPAddr {
	return &net.UDPAddr{IP: addr.(*net.UDPAddr).IP,
		Port: addr.(*net.UDPAddr).Port}
}

func DtlsClientHelloParser(conf ListenerParams) {
	flowMapper := &SNIFlowMapper{SniMappings: conf.SniMappings}
	listenAddr := fmt.Sprintf("%s:%d", conf.ListenAddr.String(), conf.Port)
	conn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		log.Fatalf("failed to start local server. %s\n", err)
	}

	defer conn.Close()
	conns := make(map[net.Addr]*DtlsConn)
	for {
		buf := make([]byte, 1526)
		count, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Errorf("failed to read from socket %s \n", err)
			continue
		}

		buf = buf[0:count]
		log.Debugf("got %d:%d bytes from: %s. \nconns:%s\n", count, len(buf), addr.String(), conns)
		_, ok := conns[addr]
		if !ok {
			log.Debugf("no connection found for addr: %s", addr.String())
			dtlsConn := &DtlsConn{
				packets:    make([][]byte, 0),
				clientAddr: toUDPAddr(addr),
				listenAddr: &net.UDPAddr{IP: conf.ListenAddr, Port: int(conf.Port)},
				timestamp:  time.Now().UnixNano(),
			}
			conns[addr] = dtlsConn
		}
		log.Debugf("connections: %s", conns)

		conns[addr].packets = append(conns[addr].packets, buf)
		go processPacket(conns[addr], flowMapper, conf.Redirects, conf.SourceNat)
	}
}
