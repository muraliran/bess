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
  struct napt_mapping_entry entry[MAX_MAP_ENTRIES];
  int num_entries;
};


static struct snobj *napt_init(struct module *m, struct snobj *arg)
{
	struct napt_priv *priv = get_priv(m);

	log_info("NAPT:napt_init\n");
 	
	// hardcode the nat IP
	priv->nat_ip = htonl(IPv4(192, 168, 10, 4));
	priv->ether_type_ipv4 = htons(ETHER_TYPE_IPv4);
	priv->entry[0].in_ip  = htonl(IPv4(192, 168, 10, 2));
	priv->entry[0].out_ip = htonl(IPv4(192, 168, 10, 3));
	priv->entry[0].in_port = htons(26001);
	priv->entry[0].out_port = htons(22);
	priv->entry[0].nat_port = htons(44001);
	priv->num_entries = 1;
	
	log_info("---NAPT ENTRY---\n");	

	log_info("IN:  ");
	log_info_ip(priv->entry[0].in_ip);
	log_info(":%d\n", priv->entry[0].in_port);
	
	log_info("NAT: ");
	log_info_ip(priv->nat_ip);
	log_info(":%d\n", priv->entry[0].nat_port);
	
	log_info("OUT: ");
	log_info_ip(priv->entry[0].out_ip);
	log_info(":%d\n", priv->entry[0].out_port);

	
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


static int outbound_flow_match(struct ipv4_hdr *ip,
			       struct napt_mapping_entry *entry,
			       uint16_t *src_port,
			       uint16_t *dst_port)
{
  return ( ip->src_addr == entry->in_ip   &&
	   *src_port    == entry->in_port &&
	   ip->dst_addr == entry->out_ip  &&
	   *dst_port    == entry->out_port );
}


static int inbound_flow_match(struct ipv4_hdr *ip,
			      struct napt_priv *priv,
			      struct napt_mapping_entry *entry,
			      uint16_t *src_port,
			      uint16_t *dst_port)
{
  return ( ip->dst_addr == priv->nat_ip &&
	   *dst_port    == entry->nat_port &&
	   ip->src_addr == entry->out_ip &&
	   *src_port    == entry->out_port );
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
	struct napt_mapping_entry *entry = &(priv->entry[0]);
	
	log_info("---------------------\n");	
	log_info("napt_process_batch %d\n", batch->cnt);	
	for (int i = 0; i < batch->cnt; i++) {

    		// get the direction of the flow
		direction[i] = get_igate();
		eth = (struct ether_hdr *)snb_head_data(batch->pkts[i]);
		
		// act only on IPv4 packets
		if ( eth->ether_type != priv->ether_type_ipv4 ){
		  log_info("Not an IPv4 packet, skip.\n");
		  continue;
		}

		log_info("direction %d\n", direction[i]);    
		log_info("packet %d\n", i);

		ip = (struct ipv4_hdr *)(eth + 1);

		log_info_ip(ip->src_addr);
		log_info(" -> ");
		log_info_ip(ip->dst_addr);
		log_info("\n");

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
		  log_info("unsupported protocol type\n");
		  continue;
		}

		log_info_ip(ip->src_addr);
		log_info(":%d ->", ntohs(*src_port));
		log_info_ip(ip->dst_addr);
		log_info(":%d\n", ntohs(*dst_port));
		
		if (direction[i] == OUTBOUND) {
		  log_info("OUTBOUND\n");
		  // check for an existing entry
		  if (outbound_flow_match(ip, entry, src_port, dst_port)) {
		    // rewrite source ip:port
		    ip->src_addr = priv->nat_ip;
		    *src_port = entry->nat_port;
		    log_info("source ip:port rewritten\n");
		  }
		  else{
		    log_info("entry not found\n");
		    continue;
		  }
		}
		else if (direction[i] == INBOUND) {
		  log_info("INBOUND\n");
		  // check for an existing entry in priv->map
		  if (inbound_flow_match(ip, priv, entry, src_port, dst_port)) {
		    // rewrite destination ip/port
		    ip->dst_addr = entry->in_ip;
		    *dst_port = entry->in_port;
		    log_info("destination ip:port rewritten\n");
		  }
		  else{
		    log_info("entry not found\n");
		    continue;
		  }
		}
		else {
		  log_info("ERROR: invalid direction");
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
