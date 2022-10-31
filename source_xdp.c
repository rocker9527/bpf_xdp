#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>



BPF_HASH(l2, struct ethhdr, int, 100);
BPF_HASH(l3_ip, struct iphdr, int, 100);
BPF_HASH(l4_tcp, struct tcphdr, int, 100);
BPF_HASH(l4_udp, struct udphdr, int, 100);
BPF_STACK(block_proto, int, 10);
BPF_STACK(block_port, int, 10);

int capture(struct xdp_md *ctx){
  int zero = 0;
  int proto;
  if(block_proto.pop(&proto) < 0)
    proto = 0;
  block_proto.push(&proto, 0);
  int port;
  if(block_port.pop(&port) < 0)
    port = 0;
  block_port.push(&port, 0);
  bpf_trace_printk("%x %x", proto, port);
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;
  struct ethhdr *eth = data;
  
  /* Ethernet */

  if((void*)eth + sizeof(*eth) <= data_end){
    l2.lookup_or_try_init(eth, &zero);
    
    /* IPv4 */ 
    
    if(htons(eth->h_proto) == ETH_P_IP){
      if(htons(proto) & ETH_P_IP)
        return XDP_DROP;
      else{
        struct iphdr *iph = data + sizeof(*eth);
        if((void*)iph + sizeof(*iph) <= data_end){
          l3_ip.lookup_or_try_init(iph, &zero); 
          if(iph->protocol == IPPROTO_TCP){
            struct tcphdr *tcph = data + sizeof(*iph) + sizeof(*iph);
            if((void*)tcph + sizeof(*tcph) <= data_end){
            if(((proto & IPPROTO_TCP) & (tcph->dest & port)) || ((proto == 0) & (tcph->dest & port)) || ((proto & IPPROTO_TCP) & (port == 0)))
              return XDP_DROP;
            else{
              
              /* TCP */
              
                l4_tcp.lookup_or_try_init(tcph, &zero);
                }
              }
            }
        if(iph->protocol == IPPROTO_UDP){
          struct udphdr *udph = data + sizeof(*iph) + sizeof(*iph);
          if((void*)udph + sizeof(*udph) <= data_end){
           if(((proto & IPPROTO_UDP) & (udph->dest & port)) || ((proto == 0) & (udph->dest & port)) || ((proto & IPPROTO_UDP) & (port == 0)))
            return XDP_DROP;
          else{
            
            /* UDP */
            
            
            
              l4_udp.lookup_or_try_init(udph, &zero);
              }
            }
          }
        }
      }
    }
  }
  return XDP_PASS;
}