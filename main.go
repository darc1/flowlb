package main

import (
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

var (
	debug bool = true
)

func main() {

	conf := ParseConfig("conf.yaml")
	//fileName := "assets/forwarder.c"
	//module := LoadTcModule(fileName, conf.Interface)
	//defer CloseTcModule(module, conf.Interface)

  fileName := "assets/xdp2_forwarder.c"
  module := LoadXdpModule(fileName, conf.Interface )
  defer CloseXdp(module, conf.Interface)
	CreatePortsTable([]uint16{conf.Port}, module)
	redirets := CreateRedirectsTable(module)
  srcNat := CreateSrcNatTable(module)
	udpEventChannel, udpPerf := CreateEventChannels(module, "udp_events")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	listenerParams := ListenerParams{
		Port:        conf.Port,
		ListenAddr:  conf.ListenAddr,
		SniMappings: conf.SniMappings,
		Redirects:   redirets,
    SourceNat: srcNat,
	}

	log.Debugf("waiting for events ...\n")
	go func() { ReadBpfEvents(udpEventChannel) }()
	go func() { DtlsClientHelloParser(listenerParams) }()

	udpPerf.Start()
	<-sig
	udpPerf.Stop()
}
