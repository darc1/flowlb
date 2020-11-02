//#define KBUILD_MODNAME "forwarder"
//#define asm_volatile_goto(x...)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/inet.h>

//#define DEBUG 1
#define PROTO_UDP 17

#define TOTAL_UDP_HLEN ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr)

// L3/L4 offsets
#define L3_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define L4_SRC_PORT_OFF                                                            \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define L4_DST_PORT_OFF                                                            \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define L4_CSUM_OFF                                                            \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))

struct udp_redirect_t{
  __u32 dst_addr;
  __u16 dst_port;
  __u32 src_addr;
  __u16 src_port;
}__attribute__((packed));

struct event_t {
  __u32 src_addr;
  __u16 src_port;
  __u32 dst_addr;
  __u16 dst_port;
  char message[128];
  __s32 code;
} __attribute__((packed));

// udp events channel
BPF_PERF_OUTPUT(udp_events);

//listening ports map 
BPF_HASH(ports, __u16, __u8);

BPF_HASH(redirects, struct udp_redirect_t, struct udp_redirect_t);
BPF_HASH(src_nat, struct udp_redirect_t, struct udp_redirect_t);

static inline void fire_event(struct __sk_buff *skb, const char *message, __s32 code){
#ifdef DEBUG
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip = (data + sizeof(struct ethhdr));
  struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
  struct event_t event = {};

  // return early if not enough data
  if (data + TOTAL_UDP_HLEN>data_end) {
    return;
  }

  // only IP packets are allowed
  if (eth->h_proto != htons(ETH_P_IP)) {
    return ;
  }

  // only UDP
  if (ip->protocol != PROTO_UDP) {
    return ;
  }


  if(ip != NULL){
  event.src_addr = ip->saddr;
  event.dst_addr = ip->daddr;
  }

  if(udp != NULL){
  event.src_port = udp->source;
  event.dst_port = udp->dest;
  }

  event.code = htonl(code);
  if(message!=NULL){
    __builtin_memcpy(&event.message, message, 127); 
  }else{
    __builtin_memcpy(&event.message, "", 127); 
  }
  udp_events.perf_submit(skb, &event, sizeof(event));
#endif

}


// mutates the given packet buffer: set L2-L4 fields, recalculate checksums
// if fwd_packet is true, we'll clone and forward the packet
// returns 0 on success, negative on failure
static inline int mutate_packet(struct __sk_buff *skb, struct udp_redirect_t *redirect)
{
    __s32 ret;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    struct bpf_fib_lookup fib_params;
    struct event_t event = {};
    
    // return early if not enough data
    if (data + TOTAL_UDP_HLEN > data_end){
        return -1;
    }

    // only IP packets are allowed
    if (eth->h_proto != htons(ETH_P_IP)){
        return -1;
    }

    // grab original destination addr
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __be16 dst_port = udp->dest;
    __be16 src_port = udp->source;


    __builtin_memset(&fib_params, 0, sizeof(fib_params));
    fib_params.family       = AF_INET;
    fib_params.tos          = ip->tos;
    fib_params.l4_protocol  = ip->protocol;
    fib_params.sport        = 0;
    fib_params.dport        = 0;
    fib_params.tot_len      = bpf_ntohs(ip->tot_len);
    fib_params.ipv4_src     = src_ip;
    fib_params.ipv4_dst     = redirect->dst_addr;
    fib_params.ifindex      = skb->ingress_ifindex;

    ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);

    if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
        fire_event(skb, "fib lookup failed", 9);
        return -1;
    }

      // set smac/dmac addr
    bpf_skb_store_bytes(skb, 0, &fib_params.dmac, sizeof(fib_params.dmac), 0);
    bpf_skb_store_bytes(skb, ETH_ALEN, &fib_params.smac, sizeof(fib_params.smac), 0);


#define SET_CSUM
#ifdef SET_CSUM
    // this is done on the NIC ???
    // recalc checksum
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, dst_ip, redirect->dst_addr, sizeof(redirect->dst_addr));
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, src_ip, redirect->src_addr, sizeof(redirect->src_addr));
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, dst_port, redirect->dst_port, sizeof(redirect->dst_port));
    bpf_l4_csum_replace(skb, L4_CSUM_OFF, src_port, redirect->src_port, sizeof(redirect->src_port));
  	bpf_l3_csum_replace(skb, L3_CSUM_OFF, dst_ip, redirect->dst_addr, sizeof(redirect->dst_addr));
  	bpf_l3_csum_replace(skb, L3_CSUM_OFF, src_ip, redirect->src_addr, sizeof(redirect->src_addr));
    #endif

    // set src/dst addr
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &(redirect->src_addr), sizeof(redirect->src_addr), 0);
    bpf_skb_store_bytes(skb, IP_DST_OFF, &(redirect->dst_addr), sizeof(redirect->dst_addr), 0);
    bpf_skb_store_bytes(skb, L4_SRC_PORT_OFF, &(redirect->src_port), sizeof(redirect->src_port), 0);
    bpf_skb_store_bytes(skb, L4_DST_PORT_OFF, &(redirect->dst_port), sizeof(redirect->dst_port), 0);
	//	bpf_skb_store_bytes(skb, L3_CSUM_OFF, &z16, sizeof(ip->check), 0);
	//	bpf_skb_store_bytes(skb, L4_CSUM_OFF, &z16, sizeof(udp->check), 0);

    
		return bpf_clone_redirect(skb, fib_params.ifindex, 0);
}
static inline int forward(struct __sk_buff *skb) {
  __s32 ret;
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip = (data + sizeof(struct ethhdr));
  struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
  struct udp_redirect_t udp_session_key = {};
  struct udp_redirect_t *udp_change = NULL;

  // return early if not enough data
  if (data + TOTAL_UDP_HLEN>
      data_end) {
    return NULL;
  }

  // only IP packets are allowed
  if (eth->h_proto != htons(ETH_P_IP)) {
    return NULL;
  }

  fire_event(skb, "got packet", 0);
  // only UDP
  if (ip->protocol != PROTO_UDP) {
    return NULL;
  }

  if (ports.lookup(&(udp->dest))) {
    udp_session_key.src_addr = ip -> saddr;
    udp_session_key.src_port = udp -> source;
    udp_session_key.dst_addr = ip -> daddr;
    udp_session_key.dst_port = udp -> dest;
    udp_change = redirects.lookup(&udp_session_key);
    if (udp_change == NULL){
      fire_event(skb, "src redirect not found", -3);
      return NULL;
    }

    ret = mutate_packet(skb, udp_change);
    fire_event(skb,  "redirected packet.", ret);
    return ret;

  }else if(ports.lookup(&(udp->source))){
    udp_session_key.src_addr = ip -> daddr;
    udp_session_key.src_port = udp -> dest;
    udp_session_key.dst_addr = ip -> saddr;
    udp_session_key.dst_port = udp -> source;
    
    udp_change = src_nat.lookup(&udp_session_key);
    if(udp_change == NULL){
      fire_event(skb, "no snat entry found", -10);
      return NULL;
    }

    ret = mutate_packet(skb, udp_change);
    fire_event(skb,  "redirected src nat packet.", ret);
    return ret;
  }else{
    fire_event(skb, "dst port is not managed", -2);
    return NULL;
  }
  
}

// main entrypoint
// returns TC_ACT_*
int forwarder(struct __sk_buff *skb) {
  return forward(skb);
}
