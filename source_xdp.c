#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <linux/in.h>


BPF_HASH(l2, struct ethhdr, int, 100);
//BPF_HASH(l3_ip, struct iphdr, int, 100);
//BPF_HASH(l4_tcp, struct tcphdr, int, 100);
//BPF_HASH(l4_udp, struct udphdr, int, 100);
//BPF_STACK(block_proto, int, 10);
//BPF_STACK(block_port, int, 10);
BPF_HASH(block, int, uint16, 10);

struct pkt
{
  struct xdp_md *ctx;
  struct ethhdr *eth;
  struct arphdr *arph;
  struct iphdr *iph;
  struct icmphdr *icmph;
  struct tcphdr *tcph;
  struct udphdr *udph;
  struct dnshdr *dnsh;
};


int process_eth(struct pkt *p){
  int tmp = -1;
  if(block.lookup(&tmp))//block all traffic
    return XDP_DROP;
  struct ethhdr *eth = p->ctx->data;
  if((void*)eth + sizeof(*eth) > p->ctx->data_end)
    return XDP_DROP; //malformed packet
  p->eth = eth;
  if(block.lookup(htons(eth->h_proto)))//block network layer protocol
    return XDP_DROP;
  if(htons(eth->h_proto) == ETH_P_IP)
      return process_ip(p);
  if(htons(eth->h_proto) == ETH_P_ARP)
      return process_arp(p);
}


int process_ip(struct pkt *p){
  struct iphdr *iph = p->ctx->data + sizeof(*(p->eth));
  if((void*)iph + sizeof(*iph) <= p->ctx->data_end)
    return XDP_DROP;
  p->iph = iph;
  if(p->iph->protocol == IPPROTO_TCP)
    return process_tcp(p);
  if(p->iph->protocol == IPPROTO_UDP)
    return process_udp(p);
  if(p->iph->protocol == IPPROTO_ICMP)
    return process_icmp(p);
}


int process_arp(struct pkt *p){
  struct arphdr *arph = p->ctx->data + sizeof(*(p->eth));
  if((void*)arph + sizeof(*arph) <= p->ctx->data_end)
    return XDP_DROP;
  p->arph = arph;
  return XDP_PASS;
}


int process_icmp(struct pkt *p){
  struct icmphdr *icmph = (struct icmphdr*)(p->iph + sizeof(*(p->iph)));
  if((void*)icmph + sizeof(*icmph) > p->ctx->data_end)
    return XDP_DROP;
  p->icmph = icmph;
  return XDP_PASS;
}


int process_tcp(struct pkt *p){
  struct tcphdr *tcph = (struct tcphdr*)(p->iph + sizeof(*(p->iph)));
  if((void*)tcph + sizeof(*tcph) > p->ctx->data_end)
    return XDP_DROP;
  p->tcph = tcph;
  if((block.lookup(&(p->iph->protocol)) & p->tcph->dest) == p->tcph->dest)
    return XDP_DROP;  
  return XDP_PASS;
}


int process_udp(struct pkt *p){
  struct udphdr *udph = (struct udphdr*)(p->iph + sizeof(*(p->iph)));
  if((void*)udph + sizeof(*udph) > p->ctx->data_end)
    return XDP_DROP;
  p->udph = udph;
  if((block.lookup(&(p->iph->protocol)) & p->udph->dest) == p->udph->dest)
    return XDP_DROP;  
  return XDP_PASS;
}


int capture(struct xdp_md *ctx){
  struct pkt p;
  p.ctx = ctx;
  return process_eth(&p);
}