# FlowLB
Customizable UDP Loadbalancer implemented using XDP and Golang

### Development System
* Ubuntu 20.04 with Kernel 5.4
* [BCC v0.18.0](https://github.com/iovisor/bcc/releases/tag/v0.18.0)
* [Go](https://golang.org/doc/install) version go1.16.2 linux/amd64

### System configuration
* Enable ip forwarding `sysctl -w net.ipv4.ip_forward=1`

### Run the example
```
python3 -m pip install yq
git clone https://github.com/darc1/flowlb
cd flowlb
./example/dtls_sni/run.sh
```

### Development
#### changing the xdp_forwarder.c code
install [go-bindata](https://github.com/jteeuwen/go-bindata) and run build.sh
```
go get -u github.com/jteeuwen/go-bindata/...
./build.sh
```



