package mapper

import (
	"errors"
	lb "flowlb"
	"fmt"
	"io/ioutil"
	"net"

	validator "github.com/asaskevich/govalidator"
	handshake "github.com/pion/dtls/v2/pkg/protocol/handshake"
	extension "github.com/pion/dtls/v2/pkg/protocol/extension"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const ExtensionServerNameTypeDNSHostName = 0

type SniMapping struct{
  Fqdn string `yaml:"fqdn"`
  Port uint `yaml:"port"`
  Ipv4 string `yaml:"ipv4"`
}

type Mappings struct {
  SniMappings []SniMapping `yaml:"sniMappings"`
}

func ParseConfig(configFile string) (map[string]*net.UDPAddr){

  yamlFile, err := ioutil.ReadFile(configFile)
  if err != nil {
    log.Fatal(err)
  }

  var rawConf Mappings
  err = yaml.Unmarshal(yamlFile, &rawConf)
  if err != nil {
    log.Fatal(err)
  }

  SniMappings := make(map[string]*net.UDPAddr)
  for _, mapping := range rawConf.SniMappings{
    if !validator.IsDNSName(mapping.Fqdn){
      log.Warningf("fqdn: %s is invalid", mapping.Fqdn)
    }
    
    _, ok := SniMappings[mapping.Fqdn]
    if ok {
      log.Warnf("duplicate mappings for: %s", mapping.Fqdn)
    }
    
    ipv4 := net.ParseIP(mapping.Ipv4)
    if ipv4 == nil{
      log.Errorf("failed to parse ipv4(%s) of: %s", mapping.Fqdn, mapping.Ipv4)
    }
    SniMappings[mapping.Fqdn] = &net.UDPAddr{IP:ipv4, Port: int(mapping.Port)}
  }

  return SniMappings;
}

type SNIFlowMapper struct {
	SniMappings map[string]*net.UDPAddr
}

func (mapper SNIFlowMapper) FindFlow(srcAddr *net.UDPAddr, srcPackets [][]byte) (*lb.Flow, error) {

	fg := newFragmentBuffer()
	for _, buf := range srcPackets {
		isHandshake, err := fg.push(append([]byte{}, buf...))
		if err != nil || !isHandshake {
			log.Errorf("packet not handshake type. %s,%t\n", err, isHandshake)
			return nil, errors.New("packet not handshake type")
		}
	}

	log.Infof("found handshake packet from: %s\n", srcAddr.String())
	rawHandshake := &handshake.Handshake{}
	for out, _ := fg.pop(); out != nil; out, _ = fg.pop() {
		log.Debugf("processing packet from: %s, pop size: %d\n", srcAddr.String(), len(out))
		if err := rawHandshake.Unmarshal(out); err != nil {
			log.Errorf("%s: handshake parse failed: %s\n", srcAddr.String(), err)
			continue
		}

		log.Debugf("%s: handshake found.\n", srcAddr.String())
		clientHello := rawHandshake.Message.(*handshake.MessageClientHello)
		extensions := clientHello.Extensions
		for _, ext := range extensions {

			log.Debugf("found extension: %d\n", ext.TypeValue())
			if ext.TypeValue() == ExtensionServerNameTypeDNSHostName {
				serverName := ext.(*extension.ServerName).ServerName
				log.Infof("found SNI extension: %s\n", serverName)
				dstAddr, ok := mapper.SniMappings[serverName]
				if !ok {
					log.Errorf("SNI: %s has no mapping!", serverName)
					return nil, errors.New(fmt.Sprintf("no sni mapping exists for: %s", serverName))
				}
				log.Debugf("sni: %s dst addr is: %s", serverName, dstAddr.String())
				return &lb.Flow{SrcAddr: srcAddr, DstAddr: dstAddr}, nil
			}
		}

	}

	return nil, nil

}
