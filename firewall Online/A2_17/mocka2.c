#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>


static struct nf_hook_ops hook1, hook2; 
char* ips[4] = {"192.168.60.5", "10.9.0.5" , "192.168.60.6" , "192.168.60.7"};
u32  ip_addrs[4];
int count[4]={0,0,0,0};
int p = 5;


unsigned int blockICMP(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;

   if (!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
    if(iph->protocol == IPPROTO_ICMP){
        int idx = 0;
        while(idx < 4){
            if(iph->saddr == ip_addrs[idx]){
                count[idx]++;
                if(count[idx] > p){
                    printk(KERN_WARNING "*** Dropping %p,\n", &(iph->saddr));
                    return NF_DROP;
                }
            }
            idx++;
        }
    }


    printk(KERN_WARNING "*** Accepting %p \n", &(iph->saddr));
   return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook){
     case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break; 
     case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break; 
     case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break; 
     case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break; 
     case NF_INET_FORWARD:      hook = "FORWARD";      break; 
     default:                   hook = "IMPOSSIBLE";   break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol){
     case IPPROTO_UDP:  protocol = "UDP";   break;
     case IPPROTO_TCP:  protocol = "TCP";   break;
     case IPPROTO_ICMP: protocol = "ICMP";  break;
     default:           protocol = "OTHER"; break;

   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}


int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");

   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_OUT;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);

   hook2.hook = blockICMP;
   hook2.hooknum = NF_INET_LOCAL_IN;
   hook2.pf = PF_INET;
   hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook2);
    int i;
    for(i = 0; i < 4; i++){
        in4_pton(ips[i], -1, (u8 *)&ip_addrs[i], '\0', NULL);
    }
   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   nf_unregister_net_hook(&init_net, &hook2);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");