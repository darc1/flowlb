# Flow LB
Customizable UDP Loadbalancer implemented using XDP and Golang

# How it works
The XDP program is listening on a configured UDP port, 
Once a packet arrives, if it is already exists in the Flow table the XDP program will redirect it to the appropriate endpoint, updates the last_used timestamp of the Flow.
Otherwise the packeet is sent to the userspace application, that needs to implement a the FlowMapper interface that calssifies the packet.

## Flow Mapper interface
FlowLB provides a customizable control plane logic, packets that are not mapped to a flow in the XDP module are forwarded to the userspace control plane, the FlowMapper object implemeted by the user provides the logic that maps packets to forward destination.
### Interface [listener.go](listener.go)
```go
 
 type Flow struct {
    SrcAddr *net.UDPAddr
    DstAddr *net.UDPAddr
  }

 type FlowMapper interface {
   FindFlow(srcAddr *net.UDPAddr, packets [][]byte) (*Flow, error)
 }
```

## Flow representation in XDP module:
### Flow Key:
```c
struct flow_t{
  __u32 dst_addr; // 4 bytes
  __u32 src_addr; // 4 bytes
  __u16 dst_port; // 2 bytes
  __u16 src_port; // 2 bytes
  __u32 pad; // padding
};
```

### Flow Value:
```c
struct flow_val_t{
  __u32 dst_addr;
  __u32 src_addr;
  __u16 dst_port;
  __u16 src_port;
  __u32 pad;
  __u64 last_used;
};
```

## Packet Flow
### New Flow
```
                                                +-----------------------------+                                                
                                                |   +---------------------+   |                                                
                                                |   |      FLOW-MAPPER    |   |                                                
                                                |   |      USERSPACE      |---------------------------------------+            
                                                |   |                     |   |      (4)Forward                   |            
                                                |   +---------------------+   |      SRC: 31.32.33.34:44332       |            
                                                |        ^           |        |      DST: 192.168.2.130:10000     |            
                                                |        |           | (3)    |                                   |            
                                                |  (2a)  |           | Add    |                                   |            
                                                |No Flow |           | Flow   |                                   |            
                                                |Found   |           |        |                                   |            
                                                |        |           |        |                                   |            
                                                |        |           v        |                                   v            
+------------------------+                      |    +--------------------+   |                          +--------------------+
| PACKET                 |                      |    |    XDP-FORWARDER   |----------------------------> |TARGET              |
| SRC: 10.1.1.2:55225    |           (1)        |    |    EBPF/KERNEL     |   |(2b) Flow Found           |192.168.2.5:10000   |
| DST: 31.32.33.34:10000 |------------------------------>                 |   |SRC: 31.32.33.34:44332    |                    |
|                        |                      |    |                    |   |DST: 192.168.2.130:10000  |                    |
+------------------------+                      |    |                    |   |                          +--------------------+
            ^                                   |    |                    |   |                                   |            
            |                                   |    |                    |   |                                   |            
            +--------------------------------------------                 |<--------------------------------------+            
                     (6) Response Packet:       |    |                    |   |         (5)Response Packet                     
                     SRC: 31.32.33.34:10000     |    +--------------------+   |         SRC: 192.168.2.5:10000                 
                     DST: 10.1.1.2:55225        |                             |         DST: 31.32.33.34:44332                 
                                                |                             |                                                
                                                |    FLOW-LB 31.32.33.34:10000|                                                
                                                +-----------------------------+                                                
                                                                                                                                                                
                                                                                                                                                                
(1) UDP Packet incoming
(2a) XDP module doesn't have a flow mapping, packet is sent to userspace control plane, packets are buffered in the load balancer until Flow is classified.
  (3) Userspace adds Flow mapping in XDP-Forwarder.
  (4) Buffered packets are sent to TARGET from userspace
(2b) XDP module has flow mapping, packet is forwarded directly to target.
(5) Response packet intercepted by XDP module.
(6) Packet redirected back to the original session.
```


## Configuration
configuration of common load balancer params
```
port: <listening port>
addr: "<listening addr>"
interface: "<listening interface>"
debug: <show debug output true/false>
conn_ttl_sec: <ttl of flow in seconds>
```

## Flows cleanup
The `XDPLoadBalancer` configuration has a `conn_ttl_sec` parameter and the Cleaner Loop implemented in [cleaner.go](cleaner.go) removes a flow from the Flows table once:
```
now() - flow.last_used > conn_ttl_sec
```

# Examples
### DTLS SNI Demux example 
implements a FlowMapper that use the DTLS Server Name Indication Extenstion to map the Flows to target hosts. 
##### to run:
```
./examples/dtls_sni/run.sh
```
#### Example Configurations:
##### config.yaml
[configuration](#configuration)  of common load balancer params

##### mappings.yaml
```
sniMappings:
    - fqdn: "<doamin-name>"
      ipv4: "<target-ipv4>"
      port: <target-port>
    - fqdn: "mydomain.rocks"
      ipv4: "1.2.3.4"
      port: 10001
```
