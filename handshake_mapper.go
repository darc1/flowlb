package main

import (
	"errors"
	"fmt"
	"net"

	dtls "github.com/darc1/dtls"
	log "github.com/sirupsen/logrus"
)

type SNIFlowMapper struct {
	SniMappings map[string]*net.UDPAddr
}


func (mapper SNIFlowMapper) FindFlow(srcAddr *net.UDPAddr, srcPackets [][]byte) (*Flow, error) {
  
	fg := dtls.NewFragmentBuffer()
	for _, buf := range srcPackets {
		isHandshake, err := fg.Push(append([]byte{}, buf...))
		if err != nil || !isHandshake {
			log.Errorf("packet not handshake type. %s,%t\n", err, isHandshake)
			return nil, errors.New("packet not handshake type")
		}
	}

	log.Infof("found handshake packet from: %s\n", srcAddr.String())
	rawHandshake := &dtls.Handshake{}
	for out, _ := fg.Pop(); out != nil; out, _ = fg.Pop() {
		log.Debugf("processing packet from: %s, pop size: %d\n", srcAddr.String(), len(out))
		if err := rawHandshake.Unmarshal(out); err != nil {
			log.Errorf("%s: handshake parse failed: %s\n", srcAddr.String(), err)
			continue
		}

		log.Infof("%s: handshake found.\n", srcAddr.String())
		clientHello := rawHandshake.HandshakeMessage.(*dtls.HandshakeMessageClientHello)
		extensions := clientHello.Extensions
		for _, ext := range extensions {

			log.Debugf("found extension: %d\n", ext.ExtensionValue())
			if ext.ExtensionValue() == dtls.ExtensionServerNameTypeDNSHostName {
				serverName := ext.(*dtls.ExtensionServerName).ServerName
				log.Infof("found SNI extension: %s\n", serverName)
				dstAddr, ok := mapper.SniMappings[serverName]
				if !ok {
					log.Errorf("SNI: %s has no mapping!", serverName)
          return nil, errors.New(fmt.Sprintf("no sni mapping exists for: %s", serverName))
				}
				log.Debugf("sni: %s dst addr is: %s", serverName, dstAddr.String())
        return &Flow{SrcAddr: srcAddr, DstAddr: dstAddr}, nil
			}
		}

	}

  return nil, nil

}
