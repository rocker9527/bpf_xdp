//#define KBUILD_MODNAME "udp_counter"
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

int capture(struct xdp_md *ctx){

  int zero = 0;
  int ss = 0;
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;
  struct ethhdr *eth = data;

  /* Ethernet */

  if((void*)eth + sizeof(*eth) <= data_end)
  {

    l2.lookup_or_try_init(eth, &zero);
    
    /* IPv4 */ 
    
    if(eth->h_proto == 8){

      struct iphdr *iph = data + sizeof(*eth);

      if((void*)iph + sizeof(*iph) <= data_end){

        l3_ip.lookup_or_try_init(iph, &zero);

        if(iph->protocol == IPPROTO_TCP){

          /* TCP */

          struct tcphdr *tcph = data + sizeof(*iph) + sizeof(*iph);
          if((void*)tcph + sizeof(*tcph) <= data_end){
            l4_tcp.lookup_or_try_init(tcph, &zero);
          }
        }

        if(iph->protocol == IPPROTO_UDP) {

          /* UDP */

          struct udphdr *udph = data + sizeof(*iph) + sizeof(*iph);
          if((void*)udph + sizeof(*udph) <= data_end){
            l4_udp.lookup_or_try_init(udph, &zero);
          }

        }
    }
  }
  }
  return XDP_PASS;
}


