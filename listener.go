package lb

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
)

type ListenerParams struct {
	Port        uint16
	ListenAddr  net.IP
	Flows   *bpf.Table
	FlowMapper  FlowMapper
	ConnTracker *ConnTracker
}

type Flow struct {
	SrcAddr *net.UDPAddr
	DstAddr *net.UDPAddr
}

type ConnTracker struct {
	Conns *sync.Map
}

func (tracker *ConnTracker) newConn(key net.Addr, listenAddr *net.UDPAddr) *TrackedConn {
	trackedConn := &TrackedConn{
		packets:    make([][]byte, 0),
		clientAddr: toUDPAddr(key),
		listenAddr: listenAddr,
		timestamp:  time.Now().UnixNano(),
	}

	tracker.Conns.Store(key, trackedConn)
	return trackedConn
}

func (tracker *ConnTracker) findConn(key net.Addr) *TrackedConn {
	conn, ok := tracker.Conns.Load(key)
	if !ok {
		return nil
	}

	return conn.(*TrackedConn)
}

func (tracker *ConnTracker) appendPacket(key net.Addr, packet []byte) error {
	conn := tracker.findConn(key)
	if conn == nil {
		return errors.New(fmt.Sprintf("Conn %s doesn't exists", key))
	}

	conn.packets = append(conn.packets, packet)
	return nil
}

func (tracker *ConnTracker) String() string {
	var sb strings.Builder
	tracker.ForEach(func(key net.Addr, val *TrackedConn) bool {
		sb.WriteString(val.String())
		sb.WriteString("\n")
		return true
	})

	return sb.String()
}

func (tracker *ConnTracker) ForEach(function func(key net.Addr, conn *TrackedConn) bool) {
	tracker.Conns.Range(func(k, v interface{}) bool {
		keyCast := k.(net.Addr)
		connCast := v.(*TrackedConn)
		return function(keyCast, connCast)
	})
}

func (tracker *ConnTracker) deleteConn(key net.Addr) {
	conn := tracker.findConn(key)
	if conn != nil {
		conn.Close()
	}
	tracker.Conns.Delete(key)
}

type FlowMapper interface {
	FindFlow(srcAddr *net.UDPAddr, packets [][]byte) (*Flow, error)
}

func sendAllBuffered(trackedConn *TrackedConn) {
	for _, buf := range trackedConn.packets {
		trackedConn.natConn.Write(buf)
	}

	trackedConn.packets = nil
}

func addFlowsTableEntry(flows *bpf.Table, conn *TrackedConn) {

	tableKey, tableValue, err := conn.getFlowValues()
	if err != nil {
		log.Warnf("failed to create flows table key/value %s", err)
		return
	}
	err = flows.SetP(unsafe.Pointer(tableKey), unsafe.Pointer(tableValue))

	if err != nil {
		log.Debugf("failed to update flows table (%s -> %s) : %s", conn.clientAddr.String(), conn.dstAddr.String(), err)
		return
	} else {
		log.Debugf("updated flows table ((%s->%s) ---> (%s->%s))",
			conn.clientAddr.String(), conn.listenAddr.String(), conn.snatAddr.String(), conn.dstAddr.String())
	}

	natTableKey, natTableValue, err := conn.getSrcNatValues()
	if err != nil {
		log.Warnf("failed to create flows nat table key/values %s", err)
		return
	}
	err = flows.SetP(unsafe.Pointer(natTableKey), unsafe.Pointer(natTableValue))

	if err != nil {
		log.Debugf("failed to update flows nat table (%s -> %s) : %s", conn.snatAddr.String(), conn.dstAddr.String(), err)
	} else {

		log.Debugf("updated flows nat table ((%s->%s) ---> (%s->%s))",
			conn.clientAddr.String(), conn.listenAddr.String(), conn.snatAddr.String(), conn.dstAddr.String())
	}
}

func forwardPackets(conn *TrackedConn, flows *bpf.Table,  socketAllocator SocketAllocator) {
	soc, err := socketAllocator.Allocate(conn.dstAddr)
	if err != nil {
		log.Errorf("failed to open UDP connection to: %s, %s", conn.dstAddr, err)
		return
	}
	log.Debugf("opened socket from: %s to %s", soc.LocalAddr().String(), conn.dstAddr.String())
	conn.natConn = soc
	conn.snatAddr = soc.LocalAddr()
	err = conn.setByteOrderedValues()
	if err != nil {
		log.Warnf("failed to set byteordered values on conn")
	}

	addFlowsTableEntry(flows, conn)
	sendAllBuffered(conn)
}

func processPacket(conn *TrackedConn, flowMapper FlowMapper, flows *bpf.Table, socketAllocator SocketAllocator) {
  start := time.Now()
	addr := conn.clientAddr
	packets := conn.packets

	flow, err := flowMapper.FindFlow(addr, packets)
  flowTime := time.Since(start)
  if err != nil {
		log.Errorf("failed to parse conn: %s", err)
		return
	}

	if flow == nil {
		log.Debugf("flow not found %s", addr.String())
		return
	}

	conn.dstAddr = flow.DstAddr
  forwardStart := time.Now()
	forwardPackets(conn, flows, socketAllocator)
  log.Infof("packet from: %s processing time total=%s, flow=%s, forwarding=%s", conn.clientAddr, time.Since(start), flowTime, time.Since(forwardStart))
}

func Listen(conf ListenerParams) {
	flowMapper := conf.FlowMapper
	connTracker := conf.ConnTracker
	socketAllocator := NewFlowSocketAllocator(&conf.ListenAddr)
	listenAddr := &net.UDPAddr{IP: conf.ListenAddr, Port: int(conf.Port)}
	conn, err := net.ListenPacket("udp", listenAddr.String())
	if err != nil {
		log.Fatalf("failed to start local server. %s\n", err)
	}

	defer conn.Close()
	for {
		buf := make([]byte, 1526)
		count, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Errorf("failed to read from socket %s \n", err)
			continue
		}

		buf = buf[0:count]
		log.Debugf("got %d bytes from: %s.", count, addr.String())
		conn := connTracker.findConn(addr)
		if conn == nil {
			log.Debugf("no connection found for addr: %s", addr.String())
			conn = connTracker.newConn(addr, listenAddr)
		}

		log.Debugf("connections: %s", connTracker)

		connTracker.appendPacket(addr, buf)
		go processPacket(connTracker.findConn(addr), flowMapper, conf.Flows,  &socketAllocator)
	}
}
