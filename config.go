package lb

import (
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	"net"
	"gopkg.in/yaml.v2"
)



type RawConfig struct{
  Port uint16 `yaml:"port"`
  Addr string `yaml:"addr"`
  Interface string `yaml:"interface"`
  ConnTTLSec uint64 `yaml:"conn_ttl_sec"`
  Debug bool `yaml:"debug"`
}



type Config struct{
  Port uint16
  ListenAddr net.IP
  Interface string
  Debug bool
  ConnTTLSec uint64
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
  conf.Debug = rawConf.Debug
  conf.ConnTTLSec = rawConf.ConnTTLSec
  
  log.Debugf("%+v", conf)
  return &conf;
}
