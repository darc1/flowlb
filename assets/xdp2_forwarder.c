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
#define MAX_UDP_LENGTH 1480

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
	__u8 smac[6];
	__u8 dmac[6];
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

__attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
  int i;
  #pragma unroll
  for (i = 0; i < 4; i ++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__))
static inline void ipv4_csum_inline(void *iph, __u64 *csum) {
  __u16 *next_iph_u16 = (__u16 *)iph;
  #pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
     *csum += *next_iph_u16++;
  }
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void ipv4_csum(void *data_start, int data_size,  __u64 *csum) {
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    // ~HC 
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    // + m
    *csum += new_addr;
    // then fold and complement result ! 
    *csum = csum_fold_helper(*csum);
}

static inline void fire_event(struct CTXTYPE *skb, const char *message, __s32 code){
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

	if(eth != NULL){
		__builtin_memcpy(&event.smac, eth -> h_source, 6);
		__builtin_memcpy(&event.dmac, eth -> h_dest, 6);
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
static inline int mutate_packet(struct CTXTYPE *skb, struct udp_redirect_t *redirect)
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
        return XDP_PASS;
    }

    // only IP packets are allowed
    if (eth->h_proto != htons(ETH_P_IP)){
        return XDP_PASS;
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
    fib_params.ipv4_src     = redirect->src_addr;
    fib_params.ipv4_dst     = redirect->dst_addr;
    fib_params.ifindex      = skb->ingress_ifindex;

    ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);

    if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
        fire_event(skb, "fib lookup failed", 9);
        return XDP_DROP;
    }

      // set smac/dmac addr
    //bpf_skb_store_bytes(skb, 0, &fib_params.dmac, sizeof(fib_params.dmac), 0);
    //bpf_skb_store_bytes(skb, ETH_ALEN, &fib_params.smac, sizeof(fib_params.smac), 0);

    __builtin_memcpy(&eth->h_dest, fib_params.dmac, ETH_ALEN);
    __builtin_memcpy(&eth->h_source, fib_params.smac, ETH_ALEN);

    ip -> saddr = redirect -> src_addr;
    ip -> daddr = redirect -> dst_addr;
    udp -> source = redirect -> src_port;
    udp -> dest = redirect -> dst_port;

		__u64 csum = 0;
    ip -> check = 0;
		ipv4_csum(ip, sizeof(struct iphdr), &csum);
		ip -> check = csum;

		csum = udp->check;
		update_csum(&csum, src_ip, ip->saddr);
		update_csum(&csum, src_port, udp->source);
		update_csum(&csum, dst_ip, ip->daddr);
		update_csum(&csum, dst_port, udp->dest);
    udp->check = csum;
		return XDP_TX;
		//return bpf_redirect(fib_params.ifindex, 0);
}
static inline int forward(struct CTXTYPE *skb) {
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
    return XDP_PASS;
  }

  // only IP packets are allowed
  if (eth->h_proto != htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // only UDP
  if (ip->protocol != PROTO_UDP) {
    return XDP_PASS;
  }
  fire_event(skb, "got packet", 0);

  if (ports.lookup(&(udp->dest))) {
    udp_session_key.src_addr = ip -> saddr;
    udp_session_key.src_port = udp -> source;
    udp_session_key.dst_addr = ip -> daddr;
    udp_session_key.dst_port = udp -> dest;
    udp_change = redirects.lookup(&udp_session_key);
    if (udp_change == NULL){
      fire_event(skb, "src redirect not found", -3);
      return XDP_PASS;
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
      return XDP_PASS;
    }

    ret = mutate_packet(skb, udp_change);
    fire_event(skb,  "redirected src nat packet.", ret);
    return ret;
  }else{
    fire_event(skb, "dst port is not managed", -2);
    return XDP_PASS;
  }
  
}

// main entrypoint
// returns TC_ACT_*
int forwarder(struct CTXTYPE *skb) {
  return forward(skb);
}
