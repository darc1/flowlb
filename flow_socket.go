package lb

import (
	"errors"
	"net"
	"sync"
)

const (
	MIN_PORT      = 10000
	MAX_PORT      = 65530
	ALLOWED_PORTS = MAX_PORT - MIN_PORT
)

func toUDPAddr(addr net.Addr) *net.UDPAddr {
	return &net.UDPAddr{IP: addr.(*net.UDPAddr).IP,
		Port: addr.(*net.UDPAddr).Port}
}

type Socket interface {
	Close() error
	LocalAddr() *net.UDPAddr
	Write(buf []byte) (int, error)
}

// Socket Allocater interface for allocating flow forwarding ports
type SocketAllocator interface {
	Allocate(dst *net.UDPAddr) (Socket, error)
}


type SocketMap struct {
  mutex *sync.Mutex
	freePorts  map[uint16]bool
}

func newSocketMap() SocketMap {
	freePorts := make(map[uint16]bool)
  for i := MIN_PORT; i <= MAX_PORT; i++ {
		freePorts[uint16(i)] = true
	}

	return SocketMap{mutex: &sync.Mutex{}, freePorts: freePorts}
}

// FlowSocket used for NAT/REDIRECT operation
// Port is bound only when sending data, from userspace
type FlowSocket struct {
	mutex     *sync.Mutex
	allocator *FlowSocketAllocator
	localAddr *net.UDPAddr
	dstAddr   *net.UDPAddr
}

// FlowSocketAllocator allocator for FlowSockets
type FlowSocketAllocator struct {
	localIp   *net.IP
	mutex     *sync.Mutex
	allocated map[string]*SocketMap
}

func (soc *FlowSocket) Close() error {
	soc.mutex.Lock()
	err := soc.allocator.Free(soc)
	soc.localAddr = nil
	soc.dstAddr = nil
	soc.allocator = nil
	soc.mutex.Unlock()
	return err
}

func (soc *FlowSocket) LocalAddr() *net.UDPAddr {
	return soc.localAddr
}

func (soc *FlowSocket) Write(buf []byte) (int, error) {
	soc.mutex.Lock()
	if soc.dstAddr == nil {
		return 0, errors.New("socket closed")
	}
	udpSoc, err := net.DialUDP("udp", nil, soc.dstAddr)
	if err != nil {
		return 0, err
	}
	count, err := udpSoc.Write(buf)
	udpSoc.Close()
	soc.mutex.Unlock()
	return count, err
}

func NewFlowSocketAllocator(localIp *net.IP) FlowSocketAllocator {
	portMap := make(map[string]*SocketMap)
	mutex := &sync.Mutex{}
	return FlowSocketAllocator{allocated: portMap, mutex: mutex, localIp: localIp}
}

func (allocator *FlowSocketAllocator) Free(soc *FlowSocket) error {
	allocator.mutex.Lock()
	sockMap, _ := allocator.allocated[soc.dstAddr.String()]
	sockMap.freePorts[uint16(soc.localAddr.Port)] = true
	allocator.mutex.Unlock()
	return nil

}

func (allocator *FlowSocketAllocator) Allocate(dst *net.UDPAddr) (Socket, error) {
  // Check if socketMap already has an entry for dst.
	socketMap, ok := allocator.allocated[dst.String()]
	if !ok {
    // lock and create new socketMap entry.
		allocator.mutex.Lock()
		socketMap, ok = allocator.allocated[dst.String()]
		if !ok {
			newSocketMap := newSocketMap()
			allocator.allocated[dst.String()] = &newSocketMap
			socketMap = allocator.allocated[dst.String()]
		}
		allocator.mutex.Unlock()
	}

  // lock and get the first free port from socketMap
	socketMap.mutex.Lock()
	freePort := uint16(0)
	for p := range socketMap.freePorts {
		freePort = p
		break
	}
	_, ok = socketMap.freePorts[freePort]

	if !ok {
    socketMap.mutex.Unlock()
		return nil, errors.New("failed to allocate port")
	}

  // remove port from the freePorts list
	delete(socketMap.freePorts, freePort)
	socketMap.mutex.Unlock()

	ip := *(allocator.localIp)
	localAddr := &net.UDPAddr{IP: ip, Port: int(freePort)}
	return &FlowSocket{allocator: allocator, localAddr: localAddr, dstAddr: dst, mutex: &sync.Mutex{}}, nil
}

// Socket implementation using OS sockets.
// For using OSSockets needs to increase the socket number limit.
// Prefer using FlowSockets
type OSSocket struct {
	udpConn *net.UDPConn
}


func (soc *OSSocket) Write(buf []byte) (int, error) {
	return soc.udpConn.Write(buf)
}

func (soc *OSSocket) Close() error {
	if soc.udpConn != nil {
		return soc.udpConn.Close()
	}

	return errors.New("no conn found")
}

func (soc *OSSocket) LocalAddr() *net.UDPAddr {
	if soc.udpConn == nil {
		return nil
	}

	return toUDPAddr(soc.udpConn.LocalAddr())
}


// OSSocketAllocator allocator implementation using OS sockets.
// Sockets are kept open for the duration of the Flow.
type OSSocketAllocator struct {
}

// Allocate ports by using net.DialUDP 
func (allocator *OSSocketAllocator) Allocate(dst *net.UDPAddr) (Socket, error) {
	soc, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return nil, err
	}

	return &OSSocket{udpConn: soc}, err
}

