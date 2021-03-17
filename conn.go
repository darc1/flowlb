package lb

import (
	"errors"
	"fmt"
	"net"

	byteorder "github.com/moolen/udplb/byteorder"
)

type TrackedConn struct {
	packets           [][]byte
	clientAddr        *net.UDPAddr
	dstAddr           *net.UDPAddr
	natConn           Socket
	listenAddr        *net.UDPAddr
	snatAddr          *net.UDPAddr
	timestamp         int64
	byteOrderedValues *ByteOrderedValues
}

type ByteOrderedValues struct {
	clientSrcPort     [2]byte
	clientSrcIp       [4]byte
	listeningAddrPort [2]byte
	listeningAddrIp   [4]byte
	srcNatPort        [2]byte
	srcNatIp          [4]byte
	dstPort           [2]byte
	dstIp             [4]byte
}

func (conn *TrackedConn) isInstalled() bool {
  return conn.byteOrderedValues != nil
}

func (conn *TrackedConn) Close() {
	if conn.natConn != nil {
		conn.natConn.Close()
	}
}

func (conn *TrackedConn) String() string {
	return fmt.Sprintf("Conn client=%s, dst=%s, listen=%s, nat=%s, timestamp=%d, packets=%d",
		conn.clientAddr.String(), conn.dstAddr.String(), conn.listenAddr.String(),
		conn.snatAddr.String(), conn.timestamp, len(conn.packets))
}

func (conn *TrackedConn) setByteOrderedValues() error {

	if conn.clientAddr == nil {
		return errors.New("client addr not set")
	}
	if conn.listenAddr == nil {
		return errors.New("listen addr not set")
	}
	if conn.snatAddr == nil {
		return errors.New("nat addr not set")
	}
	if conn.dstAddr == nil {
		return errors.New("dst addr not set")
	}

	conn.byteOrderedValues = &ByteOrderedValues{
		clientSrcPort:     byteorder.Htons(uint16(conn.clientAddr.Port)),
		clientSrcIp:       byteorder.HtonIP(conn.clientAddr.IP),
		listeningAddrPort: byteorder.Htons(uint16(conn.listenAddr.Port)),
		listeningAddrIp:   byteorder.HtonIP(conn.listenAddr.IP),
		srcNatPort:        byteorder.Htons(uint16(conn.snatAddr.Port)),
		srcNatIp:          byteorder.HtonIP(conn.snatAddr.IP),
		dstPort:           byteorder.Htons(uint16(conn.dstAddr.Port)),
		dstIp:             byteorder.HtonIP(conn.dstAddr.IP)}

	return nil

}

func (conn *TrackedConn) getSrcNatValues() (*FlowKey, *FlowValue, error) {
	if conn.byteOrderedValues == nil {
		return nil, nil, errors.New("byteOrderedValues not set")
	}
	values := conn.byteOrderedValues

	natTableKey := FlowKey{
		dstAddr: values.srcNatIp,
		dstPort: values.srcNatPort,
		srcAddr: values.dstIp,
		srcPort: values.dstPort,
		pad:     0,
	}

	natTableValue := FlowValue{
		srcAddr:  values.listeningAddrIp,
		srcPort:  values.listeningAddrPort,
		dstAddr:  values.clientSrcIp,
		dstPort:  values.clientSrcPort,
		pad:      0,
		lastUsed: GetMonoNowNano(),
	}
	return &natTableKey, &natTableValue, nil
}

func (conn *TrackedConn) getFlowValues() (*FlowKey, *FlowValue, error) {
	if conn.byteOrderedValues == nil {
		return nil, nil, errors.New("byteOrderedValues not set")
	}
	values := conn.byteOrderedValues
	tableKey := FlowKey{
		srcAddr: values.clientSrcIp,
		srcPort: values.clientSrcPort,
		dstAddr: values.listeningAddrIp,
		dstPort: values.listeningAddrPort,
		pad:     0,
	}

	tableValue := FlowValue{
		dstAddr: values.dstIp,
		dstPort: values.dstPort,
		srcAddr: values.srcNatIp,
		srcPort: values.srcNatPort,
    pad: 0,
    lastUsed: GetMonoNowNano(),
  }

	return &tableKey, &tableValue, nil
}
