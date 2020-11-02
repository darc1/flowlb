package main

import (
  "fmt"
	"bytes"
	"encoding/binary"
	log "github.com/sirupsen/logrus"
)

type udpEvent struct {
  SrcMac  [6]byte
  DstMac  [6]byte
	SrcAddr [4]byte
	SrcPort uint16
	DstAddr [4]byte
	DstPort uint16
	Message [128]byte
	Code    int32
}

func MACStr(arr [6]byte) string{
  return fmt.Sprintf("%x:%x:%x:%x:%x:%x",
  arr[0], arr[1], arr[2], arr[3], arr[4], arr[5])
}

func ReadBpfEvents(channel <-chan []byte) {
	var message udpEvent
	for {
		data := <-channel
		err := binary.Read(bytes.NewBuffer(data), binary.BigEndian, &message)
		if err != nil {
			log.Debugf("failed to decode received data: %s\n", err)
			continue
		}
    log.Debugf("BPF-EVENT: src=<%s> %d:%d, dst=<%s> %d:%d, code=%d, message=%s\n",
      MACStr(message.SrcMac),
			message.SrcAddr,
			message.SrcPort,
      MACStr(message.DstMac),
			message.DstAddr,
			message.DstPort,
			message.Code,
			string(message.Message[:]))
	}
}
