#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <linux/in.h>


BPF_HASH(block, int, uint16, 10);
BPF_HASH(drop_count, int, int, 1);
BPF_HASH(ip_b, int, __be32, 100);
BPF_HASH(mac_b, int, u_int8_t, 100);
BPF_HASH(capture, int, int, 1);
BPF_RINGBUF_OUTPUT(packet, 8);

struct pkt{
  struct xdp_md *ctx;
  struct ethhdr *eth;
  struct arphdr *arph;
  struct iphdr *iph;
  struct icmphdr *icmph;
  struct tcphdr *tcph;
  struct udphdr *udph;
  struct dnshdr *dnsh;
};


int zero = 0;


static inline void proceed_pkt(struct pkt* p){
  int len = (int)p->ctx->data_end - p->ctx->data;
  packet.ringbuf_output(p->ctx->data, len, 0);
}


static inline void increment_drop(){
  int* val = drop_count.lookup(&zero);
  if(val)
    *val += 1; 
}
 
static inline int process_eth(struct pkt *p){
  int tmp = -1;
  if(block.lookup(&tmp)){//block all traffic
    increment_drop();
    if(capture.lookup(&zero)) 
      proceed_pkt(p);
    return XDP_DROP;
  }
  struct ethhdr *eth = p->ctx->data;
  if((void*)eth + sizeof(*eth) > p->ctx->data_end)
    return XDP_DROP; //malformed packet
  p->eth = eth;
  if(block.lookup(htons(eth->h_proto)) || mac_b.lookup(eth->h_source)){//block network layer protocol
    increment_drop();
    if(capture.lookup(&zero)) 
      proceed_pkt(p);
    return XDP_DROP;
  }
  if(htons(eth->h_proto) == ETH_P_IP)
      return process_ip(p);
  if(htons(eth->h_proto) == ETH_P_ARP)
      return process_arp(p);
}


static inline int process_ip(struct pkt *p){
  struct iphdr *iph = p->ctx->data + sizeof(*(p->eth));
  if((void*)iph + sizeof(*iph) <= p->ctx->data_end){
    increment_drop();
    if(capture.lookup(&zero)) 
      proceed_pkt(p);
    return XDP_DROP;
  }
  p->iph = iph;
  if(ip_b.lookup(iph->saddr)){
    increment_drop();
    if(capture.lookup(&zero)) 
      proceed_pkt(p);
    return XDP_DROP;
  }
  if(p->iph->protocol == IPPROTO_TCP)
    return process_tcp(p);
  if(p->iph->protocol == IPPROTO_UDP)
    return process_udp(p);
  if(p->iph->protocol == IPPROTO_ICMP)
    return process_icmp(p);
}


static inline int process_arp(struct pkt *p){
  struct arphdr *arph = p->ctx->data + sizeof(*(p->eth));
  if((void*)arph + sizeof(*arph) <= p->ctx->data_end){
    increment_drop();
    if(capture.lookup(&zero)) 
      proceed_pkt(p);
    return XDP_DROP;
  }
  p->arph = arph;
  return XDP_PASS;
}


static inline int process_icmp(struct pkt *p){
  struct icmphdr *icmph = (struct icmphdr*)(p->iph + sizeof(*(p->iph)));
  if((void*)icmph + sizeof(*icmph) > p->ctx->data_end){
    increment_drop();
    if(capture.lookup(&zero)) 
      proceed_pkt(p);
    return XDP_DROP;
  }
  p->icmph = icmph;
  return XDP_PASS;
}


static inline int process_tcp(struct pkt *p){
  struct tcphdr *tcph = (struct tcphdr*)(p->iph + sizeof(*(p->iph)));
  if((void*)tcph + sizeof(*tcph) > p->ctx->data_end)
    return XDP_DROP;
  p->tcph = tcph;
  if((block.lookup(&(p->iph->protocol)) & p->tcph->dest) == p->tcph->dest){
    increment_drop();
    if(capture.lookup(&zero)) 
      proceed_pkt(p);
    return XDP_DROP;  
  }
  return XDP_PASS;
}


static inline int process_udp(struct pkt *p){
  struct udphdr *udph = (struct udphdr*)(p->iph + sizeof(*(p->iph)));
  if((void*)udph + sizeof(*udph) > p->ctx->data_end)
    return XDP_DROP;
  p->udph = udph;
  if((block.lookup(&(p->iph->protocol)) & p->udph->dest) == p->udph->dest){
    increment_drop();
    if(capture.lookup(&zero)) 
      proceed_pkt(p);
    return XDP_DROP;  
  }
  return XDP_PASS;
}


int capture(struct xdp_md *ctx){
  struct pkt p;
  p.ctx = ctx;
  return process_eth(&p);
}