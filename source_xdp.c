#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/tcp.h>



BPF_HASH(l2, struct ethhdr, int, 1);
BPF_HASH(l3_ip, struct iphdr, int, 1);
BPF_HASH(l4_tcp, struct tcphdr, int, 1);
BPF_HASH(l4_udp, struct udphdr, int, 1);
BPF_STACK(block_proto, int, 10);
BPF_STACK(block_port, int, 10);
//BPF_HASH(block_adr, int, int, 100);



int capture(struct xdp_md *ctx){

  int zero = 0;
  int tmp;
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;
  struct ethhdr *eth = data;
  int port;
  int protocol;

  /* Should solve problem of using cycles and func calls */

  if(block_proto.pop(&protocol) < 0)
    protocol = -1;
  else
    block_proto.push(&protocol, 0);

  /* Ethernet */

  if((void*)eth + sizeof(*eth) <= data_end)
  {   
    l2.lookup_or_try_init(eth, &zero);

    /* IPv4 */ 

    if(protocol == ETH_P_IP){
      return XDP_DROP;
    }
    else{
      if(eth->h_proto == ETH_P_IP){
        struct iphdr *iph = data + sizeof(*eth);
        if((void*)iph + sizeof(*iph) <= data_end){  
            l3_ip.lookup_or_try_init(iph, &zero);

            if(iph->protocol == IPPROTO_TCP){
              if(protocol == IPPROTO_TCP){
                return XDP_DROP;
              }
              else{

              /* TCP */

              struct tcphdr *tcph = data + sizeof(*iph) + sizeof(*iph);
              if((void*)tcph + sizeof(*tcph) <= data_end){
                l4_tcp.lookup_or_try_init(tcph, &zero);
              }
            }
           
          if(iph->protocol == IPPROTO_UDP) {
            if(protocol == IPPROTO_UDP)
              return XDP_DROP;
            else{
            
              /* UDP */

              struct udphdr *udph = data + sizeof(*iph) + sizeof(*iph);
              if((void*)udph + sizeof(*udph) <= data_end){
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


