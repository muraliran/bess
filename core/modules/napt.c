#include "../module.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define PROTO_TYPE_ICMP 0x01
#define PROTO_TYPE_TCP  0x06
#define PROTO_TYPE_UDP  0x11
#define OUTBOUND 0
#define INBOUND  1
#define MAX_MAP_ENTRIES 1

struct napt_mapping_entry {
  struct ether_addr in_eth;
  uint32_t in_ip;
  uint32_t out_ip;
  uint16_t in_port;
  uint16_t in_mapped_port;
  uint16_t out_port;
};

struct napt_priv {
  struct ether_addr nat_addr;
  uint32_t public_ip;
  struct napt_mapping_entry entry;
};



static struct snobj *napt_init(struct module *m, struct snobj *arg)
{
  	int ip[4]; 
	struct napt_priv *priv = get_priv(m);
	
	// hardcode the NAT address to 03:03:03:03:03:03
	for (int i = 0; i < 6; i++) 
	  priv->nat_addr[i] = 0x03;

	// hardcode the public IP
	priv->public_ip = IPv4(132, 1, 1, 2);
	
	// set the public ip based on the input arg
	//	if (arg) {
	//  char *ip_str = snobj_eval_str(arg, "ip");
	//  char *octet;
	//  char *left;
	//  octet = strtok(ip_str,".");
	//  
	//  }
	  
	return NULL;
}



static void napt_process_batch(struct module *m, struct pkt_batch *batch)
{
  	int direction;
	struct ether_hdr *eth;
	struct ether_addr src_mac;
	struct ether_addr dst_mac;
	struct ipv4_hdr *ip;
	uint32_t src_ip;
	uint32_t dst_ip;
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;
	uint16_t *src_port;
	uint16_t *dst_port; 
	
	for (int i = 0; i < batch->cnt; i++) {
		eth = (struct ether_hdr *)snb_head_data(batch->pkts[i]);
		
		// act only on IPv4 packets
		if ( eth->ether_type != ETHER_TYPE_IPv4 )
		  continue;

		ip = (struct ipv4_hdr *)(eth + 1);
		
		// of type TCP (for now)
		if ( ip->next_proto_id == PROTO_TYPE_TCP ) {
		  tcp = (struct tcp_hdr *)(ip + 1);
		  src_port = &(tcp->src_port);
		  dst_port = &(tcp->dst_port);
		}
		else if (ip->next_proto_id == PROTO_TYPE_UDP ) {
		  udp = (struct udp_hdr *)(ip + 1);
		  src_port = &(udp->src_port);
		  dst_port = &(udp->dst_port);
		}
		else
		  continue;

		// get the direction of the flow
		direction = get_igate();
		struct napt_priv *priv = get_priv(m);
		struct napt_mapping_entry *entry;
		if (direction == OUTBOUND) {
		  // check for an existing entry
		  
		  entry = &(priv->entry);
		  if ( !(eth->s_addr == entry->in_eth &&
			 ip->src_addr == entry->in_ip &&
			 *src_port == entry->in_port &&
			 ip->dst_addr == entry->out_ip &&
			 *dst_port == entry->out_port ) ) {
		    // if flow doesn't exist add entry
		    entry->in_eth = eth->s_addr;
		    entry->in_ip = ip->src_addr;
		    entry->in_port = *src_port;
		    entry->out_ip = ip->dst_addr;
		    entry->out_port = *dst_port;
		    entry->in_mapped_port = 25111;
		  }
		  // rewrite the source eth to nat_eth
		  eth->s_addr = priv->nat_eth;
		  // rewrite the source ip to public_ip
		  ip->src_addr = priv->public_ip;
		  // rewrite the source port to entry->in_mapped_port 
		  *src_port = entry->in_mapped_port; 
		  // update all checksums
		 
		}
		else if (direction == INBOUND) {
		  // check for an existing entry in priv->map
		  entry = &(priv->entry);
		  if ( !(eth->d_addr == priv->nat_eth &&
			 ip->dst_addr == priv->public_ip &&
			 *dst_port == entry->in_mapped_port &&
			 ip->src_addr == entry->out_ip &&
			 *src_port == entry->out_port ) ) {
		    // if flow doesn't exist, don't do anything (continue)
		    continue;
		  }
		  // rewrite the dest eth (nat_eth) to entry->in_eth
		  eth->d_addr = entry->in_eth;
		  // rewrite the dest ip (public_ip) to entry->in_ip
		  ip->dst_addr = entry->in_ip;
		  // rewrite the dest port (entry->in_mapped_port) to entry->in_port
		  *dst_port = entry->in_port;
		  // update all checksums
		 
		}
		else {
		  // we should report an error condition, but for now just skip the packet
		  continue;
		}		
	}

	run_choose_module(m, direction, batch);
}

static const struct mclass napt = {
	.name 			= "NAPT",
	.help			= "network address port translation",
	.def_module_name	= "NAPT",
	.num_igates		= 2,
	.num_ogates		= 2,
	.priv_size	        = sizeof(struct napt_priv),
	.init 		        = napt_init,
	.process_batch 		= napt_process_batch,
};

ADD_MCLASS(napt)
