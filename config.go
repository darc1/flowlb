package main

import (
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	"net"
  validator "github.com/asaskevich/govalidator"
	"gopkg.in/yaml.v2"
)

type SniMapping struct{
  Fqdn string `yaml:"fqdn"`
  Port uint `yaml:"port"`
  Ipv4 string `yaml:"ipv4"`
}

type RawConfig struct{
  Port uint16 `yaml:"port"`
  Addr string `yaml:"addr"`
  Interface string `yaml:"interface"`
  SniMappings []SniMapping `yaml:"sniMappings"`
  SourceNat bool `yaml:sourceNat`
}

type Config struct{
  Port uint16
  ListenAddr net.IP
  Interface string
  SniMappings map[string]*net.UDPAddr
  SourceNat bool
}

func ParseConfig(configFile string) *Config{

  yamlFile, err := ioutil.ReadFile(configFile)
  if err != nil {
    log.Fatal(err)
  }

  var rawConf RawConfig
  err = yaml.Unmarshal(yamlFile, &rawConf)
  if err != nil {
    log.Fatal(err)
  }

  log.Println(rawConf)
  var conf Config
  conf.Port = rawConf.Port
  conf.ListenAddr = net.ParseIP(rawConf.Addr)
  if conf.ListenAddr == nil {
    log.Fatalf("failed to get listening addr")
  }

  iface, err := net.InterfaceByName(rawConf.Interface)
  if err != nil {
    log.Fatalf("failed to verify interface:%s, error: %s", rawConf.Interface, err)
  }

  conf.Interface = iface.Name
  conf.SniMappings = make(map[string]*net.UDPAddr)
  for _, mapping := range rawConf.SniMappings{
    if !validator.IsDNSName(mapping.Fqdn){
      log.Warningf("fqdn: %s is invalid", mapping.Fqdn)
    }
    
    _, ok := conf.SniMappings[mapping.Fqdn]
    if ok {
      log.Warnf("duplicate mappings for: %s", mapping.Fqdn)
    }
    
    ipv4 := net.ParseIP(mapping.Ipv4)
    if ipv4 == nil{
      log.Errorf("failed to parse ipv4(%s) of: %s", mapping.Fqdn, mapping.Ipv4)
    }
    conf.SniMappings[mapping.Fqdn] = &net.UDPAddr{IP:ipv4, Port: int(mapping.Port)}
  }

  conf.SourceNat = rawConf.SourceNat
  
  log.Debugf("%s", conf)
  return &conf;
}
