package main

import (
	"os"
	"os/signal"
	lb "flowlb"
	mapper "flowlb/mappers/dtls_sni"

	log "github.com/sirupsen/logrus"
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
  
  args := os.Args[1:]
  if len(args) < 2{
    log.Fatalf("missing config files.")
  }
  configFile := args[0]
  mappingFile := args[1]
	config := lb.ParseConfig(configFile)
  mappings := mapper.ParseConfig(mappingFile)
	flowMapper := mapper.SNIFlowMapper{SniMappings: mappings}
  loadBalancer := lb.XdpLoadBalancer{Config: config, FlowMapper: flowMapper}
  err := loadBalancer.Start()
  if err != nil {
    log.Fatalf("failed to start loadBalancer")
  }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
  loadBalancer.Stop()
}
