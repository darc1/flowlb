package lb

import (
	"net"
  "reflect"
  "sync"
	"testing"
)

const mutexLocked = 1
 
func MutexLocked(m *sync.Mutex) bool {
    state := reflect.ValueOf(m).Elem().FieldByName("state")
    return state.Int()&mutexLocked == mutexLocked
}

func verifyAllocation(t *testing.T, ip net.IP, socket Socket, err error) {
	if err != nil {
		t.Errorf("Socket allocation failed %s", err)
	}

	if socket.LocalAddr().Port < MIN_PORT || socket.LocalAddr().Port > MAX_PORT {
		t.Errorf("Port allocation %d not in range %d-%d", socket.LocalAddr().Port, MIN_PORT, MAX_PORT)
	}

	if socket.LocalAddr().IP.String() != ip.String() {
		t.Errorf("Wrong socket ip: %s expected: %s", socket.LocalAddr().IP.String(), ip.String())
	}

}

func TestSocketAlloctor(t *testing.T) {
	ip := net.ParseIP("10.1.1.1")
	allocator := NewFlowSocketAllocator(&ip)
	dst := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 10000}
	socket, err := allocator.Allocate(&dst)
	verifyAllocation(t, ip, socket, err)
}

func TestSocketAlloctorUniquePorts(t *testing.T) {
	ip := net.ParseIP("10.1.1.1")
	allocator := NewFlowSocketAllocator(&ip)
	dst := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 10000}
	allocated := make(map[int]bool)

	for i := MIN_PORT; i <= MAX_PORT; i++ {
		socket, err := allocator.Allocate(&dst)
		verifyAllocation(t, ip, socket, err)
		_, ok := allocated[socket.LocalAddr().Port]
		if ok {
			t.Errorf("Port: %d already allocated", socket.LocalAddr().Port)
		}
		allocated[socket.LocalAddr().Port] = true
	}

}

func TestSocketAlloctorMaxCapacity(t *testing.T) {
	ip := net.ParseIP("10.1.1.1")
	allocator := NewFlowSocketAllocator(&ip)
	dst := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 10000}
	allocated := make(map[int]bool)

	for i := MIN_PORT; i <= MAX_PORT; i++ {
		socket, err := allocator.Allocate(&dst)
		verifyAllocation(t, ip, socket, err)
		_, ok := allocated[socket.LocalAddr().Port]
		if ok {
			t.Errorf("Port: %d already allocated", socket.LocalAddr().Port)
		}
		allocated[socket.LocalAddr().Port] = true
	}

	socket, err := allocator.Allocate(&dst)
	if err == nil {
		t.Errorf("Port Allocated: %d more than allowed ports: %d", len(allocated)+1, MAX_PORT-MIN_PORT)
	}

	if socket != nil {
		t.Errorf("returned socket even after passing max allowed ports: %d", MAX_PORT-MIN_PORT)
	}
}

func TestSocketAlloctorFreePorts(t *testing.T) {
	ip := net.ParseIP("10.1.1.1")
	allocator := NewFlowSocketAllocator(&ip)
	dst := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 10000}
	allocated := make(map[int]Socket)
	for i := MIN_PORT; i <= MAX_PORT; i++ {
		socket, err := allocator.Allocate(&dst)
		verifyAllocation(t, ip, socket, err)
		allocated[socket.LocalAddr().Port] = socket
	}

	lastSocket, err := allocator.Allocate(&dst)
	if err == nil {
		t.Errorf("Port Allocated: %d more than allowed ports: %d", len(allocated)+1, MAX_PORT-MIN_PORT)
	}

	if lastSocket != nil {
		t.Errorf("returned socket even after passing max allowed ports: %d", MAX_PORT-MIN_PORT)
	}

	randomPort := 0
	for p := range allocated {
		randomPort = p
		break
	}
  
	allocated[randomPort].Close()
	socket, err := allocator.Allocate(&dst)
  t.Logf("allocated port: %d", randomPort)
	verifyAllocation(t, ip, socket, err)
	if socket.LocalAddr().Port != randomPort {
		t.Errorf("allocator port assignment mismatch expected: %d, actual: %d", randomPort, socket.LocalAddr().Port)
	}

}
