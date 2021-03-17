package lb

import (
	"errors"
	"sync"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
)

type LoadBalancer interface {
	Start() error
	Stop() error
}

type XdpLoadBalancer struct {
	Config     *Config
	FlowMapper FlowMapper
	module     *bpf.Module
	flows      *bpf.Table
	udpPerf    *bpf.PerfMap
}

func (lb *XdpLoadBalancer) Start() error {
	if lb.Config == nil {
		return errors.New("no config found")
	}

	// init xdp module
	fileName := "bpf/xdp_forwarder.c"
	lb.module = LoadXdpModule(fileName, lb.Config.Interface, lb.Config.Debug)

	// init tables
	CreatePortsTable([]uint16{lb.Config.Port}, lb.module)
	lb.flows = CreateFlowsTable(lb.module)

	// init event channel
	udpEventChannel, udpPerf := CreateEventChannels(lb.module, "udp_events")
	lb.udpPerf = udpPerf

	// create listener params
	listenerParams := CreateListenerParams(lb)
	cleaner := CreateConnectionCleaner(lb, listenerParams.ConnTracker)
	log.Debugf("waiting for events ...\n")
	go func() { ReadBpfEvents(udpEventChannel) }()
	go func() { Listen(listenerParams) }()
	go func() { cleaner.CleanLoop() }()

	udpPerf.Start()
	log.Infof("started load balancer.")

	return nil
}

func (lb *XdpLoadBalancer) Stop() error {
	log.Infof("stopping load balancer")
	if lb.udpPerf != nil {
		log.Debugf("stopping perf map")
		lb.udpPerf.Stop()
	}

	log.Debugf("closing xdp module: %+v", lb.module)
	CloseXdp(lb.module, lb.Config.Interface)
	return nil
}

func CreateConnectionCleaner(lb *XdpLoadBalancer, connTracker *ConnTracker) *ConnectionCleanerLoop {
	return &ConnectionCleanerLoop{flows: lb.flows,
		connTracker: connTracker,
		ttl_sec:     lb.Config.ConnTTLSec}

}

func CreateListenerParams(lb *XdpLoadBalancer) ListenerParams {
	return ListenerParams{
		Port:        lb.Config.Port,
		ListenAddr:  lb.Config.ListenAddr,
		Flows:       lb.flows,
		FlowMapper:  lb.FlowMapper,
		ConnTracker: &ConnTracker{Conns: new(sync.Map)},
	}
}
