package main

import (
	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"udplb/byteorder"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

func LoadTcModule(fileName string, linkName string) *bpf.Module {

	source, err := Asset(fileName)
	if err != nil {
		log.Fatal(err)
	}

	llvmArgs := []string{"-w"}
	if debug == true {
		llvmArgs = append(llvmArgs, "-DDEBUG=1")
		log.SetLevel(log.DebugLevel)
	}

	log.Info("loading bpf module.")
	module := bpf.NewModule(string(source), llvmArgs)

	log.Info("loading net module type=BPF_PROG_TYPE_SCHED_ACT\n")
	fd, err := module.LoadNet("forwarder")
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("fetch link: %s\n", linkName)
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		log.Fatal(err)
	}

	err = createQdisc(link)
	if err != nil {
		log.Fatal(err)
	}

	err = createFilter(fd, "forwarder", link, netlink.HANDLE_MIN_INGRESS)
	//err = createFilter(fd, "forwarder", link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		log.Fatal(err)
	}

	return module

}

func CloseTcModule(module *bpf.Module, linkName string) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		log.Error(err)
	} else {
		deleteQdisc(link)
	}
	module.Close()
}

func LoadXdpModule(fileName string, link_name string) *bpf.Module {

	source, err := Asset(fileName)
	if err != nil {
		log.Fatal(err)
	}

	llvmArgs := []string{"-w"}
	llvmArgs = append(llvmArgs, "-DCTXTYPE=xdp_md")
	if debug == true {
		llvmArgs = append(llvmArgs, "-DDEBUG=1")
		log.SetLevel(log.DebugLevel)
	}

	log.Info("loading bpf module.")
	module := bpf.NewModule(string(source), llvmArgs)

	log.Info("loading net module type=BPF_PROG_TYPE_XDP\n")
	fd, err := module.Load("forwarder", C.BPF_PROG_TYPE_XDP, 1, 16*65536)
	if err != nil {
		log.Fatal(err)
	}
	err = module.AttachXDP(link_name, fd)
	if err != nil {
		log.Fatal(err)
	}

	return module
}

func CloseXdp(module *bpf.Module, link_name string) {

	if err := module.RemoveXDP(link_name); err != nil {
		log.Error(err)
	}
}

func CreatePortsTable(listeningPorts []uint16, module *bpf.Module) {
	ports := bpf.NewTable(module.TableId("ports"), module)
	trueByte := []byte{1}
	for _, port := range listeningPorts {

		portBytes := byteorder.Htons(port)
		portNs := portBytes[:]
		ports.Set(portNs, trueByte)
	}

}

func CreateRedirectsTable(module *bpf.Module) *bpf.Table {
	return bpf.NewTable(module.TableId("redirects"), module)
}

func CreateSrcNatTable(module *bpf.Module) *bpf.Table {
	return bpf.NewTable(module.TableId("src_nat"), module)
}

func CreateEventChannels(module *bpf.Module, tableName string) (chan []byte, *bpf.PerfMap) {
	table := bpf.NewTable(module.TableId(tableName), module)
	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		log.Fatalf("Failed to init perf map: %s\n", err)
	}

	return channel, perfMap
}
