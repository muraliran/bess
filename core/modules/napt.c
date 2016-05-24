#include "../module.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <arpa/inet.h>

#define PROTO_TYPE_ICMP 0x01
#define PROTO_TYPE_TCP  0x06
#define PROTO_TYPE_UDP  0x11
#define OUTBOUND 0
#define INBOUND  1
#define MAX_MAP_ENTRIES 1

static void log_info_ip(uint32_t ip)
{
	char buf[16];
	const char* result=inet_ntop(AF_INET,&ip,buf,sizeof(buf));
	if (result==0) {
	  log_info("failed to convert address to string (errno=%d)",errno);
	}
	log_info("%s", buf);
}


struct napt_mapping_entry {
  uint32_t in_ip;
  uint32_t out_ip;
  uint16_t in_port;
  uint16_t out_port;
  uint16_t nat_port;
};

struct napt_priv {
  uint32_t nat_ip;
  uint32_t ether_type_ipv4;
  struct napt_mapping_entry entry;
};


static struct snobj *napt_init(struct module *m, struct snobj *arg)
{
	struct napt_priv *priv = get_priv(m);

	log_info("NAPT:napt_init\n");
 	
	// hardcode the nat IP
	priv->nat_ip = htonl(IPv4(192, 168, 10, 4));
	priv->ether_type_ipv4 = htons(ETHER_TYPE_IPv4);
	priv->entry.in_ip  = htonl(IPv4(192, 168, 10, 2));
	priv->entry.out_ip = htonl(IPv4(192, 168, 10, 3));
	priv->entry.in_port = htons(26001);
	priv->entry.out_port = htons(22);
	priv->entry.nat_port = htons(44001);

	log_info("---NAPT ENTRY---\n");	

	log_info("IN:  ");
	log_info_ip(priv->entry.in_ip);
	log_info(":%d  /  ", priv->entry.in_port);
	
	log_info("NAT: ");
	log_info_ip(priv->nat_ip);
	log_info(":%d  /  ", priv->entry.nat_port);
	log_info("OUT: ");
	log_info_ip(priv->entry.out_ip);
	log_info(":%d\n", priv->entry.out_port);


	
	// set the nat ip based on the input arg
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
  	gate_idx_t direction[MAX_PKT_BURST];
	struct ether_hdr *eth;
	struct ipv4_hdr *ip;
	void *l4;
	uint16_t *l4_cksum;
	uint16_t *src_port;
	uint16_t *dst_port; 

	struct napt_priv *priv = get_priv(m);
	struct napt_mapping_entry *entry = &(priv->entry);
	
	for (int i = 0; i < batch->cnt; i++) {

    		// get the direction of the flow
		direction[i] = get_igate();

		eth = (struct ether_hdr *)snb_head_data(batch->pkts[i]);
		
		// act only on IPv4 packets
		if ( eth->ether_type != priv->ether_type_ipv4 ){
		  continue;

		ip = (struct ipv4_hdr *)(eth + 1);
		
		// of type TCP (for now)
		l4 = (void *)(ip + 1);
		if ( ip->next_proto_id == PROTO_TYPE_TCP ) {
		  struct tcp_hdr *tcp = (struct tcp_hdr *)l4;
		  l4_cksum = &(tcp->cksum);
		  src_port = &(tcp->src_port);
		  dst_port = &(tcp->dst_port);
		}
		else if (ip->next_proto_id == PROTO_TYPE_UDP ) {
		  struct udp_hdr *udp = (struct udp_hdr *)(ip + 1);
		  l4_cksum = &(udp->dgram_cksum);
		  src_port = &(udp->src_port);
		  dst_port = &(udp->dst_port);
		}
		else{
		  continue;
		}
		
		if (direction[i] == OUTBOUND) {
		  // check for an existing entry
		  if ( ip->src_addr == entry->in_ip   &&
		       *src_port    == entry->in_port &&
		       ip->dst_addr == entry->out_ip  &&
		       *dst_port    == entry->out_port ) {
		    // rewrite source ip:port
		    ip->src_addr = priv->nat_ip;
		    *src_port = entry->nat_port;
		  }
		  else{
		    continue;
		  }
		}
		else if (direction[i] == INBOUND) {
		  // check for an existing entry in priv->map
		  if ( ip->dst_addr == priv->nat_ip &&
		       *dst_port    == entry->nat_port &&
		       ip->src_addr == entry->out_ip &&
		       *src_port    == entry->out_port ) {
		    // rewrite destination ip/port
		    ip->dst_addr = entry->in_ip;
		    *dst_port = entry->in_port;
		  }
		  else{
		    continue;
		  }
		}
		else {
		  // we should report an error condition, but for now just skip the packet
		  continue;
		}

		// update L3 checksum
		ip->hdr_checksum = 0;
		ip->hdr_checksum = rte_ipv4_cksum(ip);
				
		// update L4 checksum
		*l4_cksum = 0;
		*l4_cksum = rte_ipv4_udptcp_cksum(ip, l4);
	}

	run_split(m, direction, batch);
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
