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

struct napt_mapping_entry {
  struct ether_addr in_eth;
  uint32_t in_ip;
  uint32_t out_ip;
  uint16_t in_port;
  uint16_t out_port;
  uint16_t nat_port;
};

struct napt_priv {
  struct ether_addr nat_eth;
  uint32_t nat_ip;
  struct napt_mapping_entry entry;
};


static void log_info_eth(struct ether_addr eth)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, &eth);
	log_info("%s\n", buf);
}

static void log_info_ip(uint32_t ip)
{
	uint32_t tmp_ip = htonl(ip);
	char buf[16];
	const char* result=inet_ntop(AF_INET,&tmp_ip,buf,sizeof(buf));
	if (result==0) {
	  log_info("failed to convert address to string (errno=%d)",errno);
	}
	log_info("%s", buf);
}


static struct snobj *napt_init(struct module *m, struct snobj *arg)
{
	struct napt_priv *priv = get_priv(m);

	log_info("NAPT:napt_init\n");
 	
	// hardcode the NAT address to 00:00:00:00:00:04
	for (int i = 0; i < 5; i++) 
	  priv->nat_eth.addr_bytes[i] = 0x00;
 	priv->nat_eth.addr_bytes[5] = 0x04;

	// hardcode the nat IP
	priv->nat_ip = IPv4(192, 168, 10, 4);

	for (int i = 0; i < 5; i++) 
	  priv->entry.in_eth.addr_bytes[i] = 0x00;
	priv->entry.in_eth.addr_bytes[5] = 0x02;
	priv->entry.in_ip  = IPv4(192, 168, 10, 2);
	priv->entry.out_ip = IPv4(192, 168, 10, 3);
	priv->entry.in_port = 26001;
	priv->entry.out_port = 22;
	priv->entry.nat_port = 44001;


	log_info("---NAPT ENTRY---\n");	

	log_info("IN:  ");
	log_info_ip(priv->entry.in_ip);
	log_info(":%d  /  ", priv->entry.in_port);
	log_info_eth(priv->entry.in_eth);
	
	log_info("NAT: ");
	log_info_ip(priv->nat_ip);
	log_info(":%d  /  ", priv->entry.nat_port);
	log_info_eth(priv->nat_eth);

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
		direction[i] = get_igate();
		struct napt_priv *priv = get_priv(m);
		struct napt_mapping_entry *entry;
		if (direction[i] == OUTBOUND) {
		  // check for an existing entry
		  
		  entry = &(priv->entry);
		  if ( !(is_same_ether_addr(&(eth->s_addr),&(entry->in_eth))  &&
			 ip->src_addr == entry->in_ip   &&
			 *src_port    == entry->in_port &&
			 ip->dst_addr == entry->out_ip  &&
			 *dst_port    == entry->out_port ) ) {
		    // if flow doesn't exist add entry
		    /* entry->in_eth      = eth->s_addr; */
		    /* entry->in_ip       = ip->src_addr; */
		    /* entry->in_port     = *src_port; */
		    /* entry->out_ip      = ip->dst_addr; */
		    /* entry->out_port    = *dst_port; */
		    /* entry->nat_port = 55001; */
		  }
		  // rewrite the source eth to nat_eth
		  eth->s_addr = priv->nat_eth;
		  // rewrite the source ip to nat_ip
		  ip->src_addr = priv->nat_ip;
		  // rewrite the source port to entry->nat_port 
		  *src_port = entry->nat_port; 
		  // update all checksums
		 
		}
		else if (direction[i] == INBOUND) {
		  // check for an existing entry in priv->map
		  entry = &(priv->entry);
		  if ( !(is_same_ether_addr(&(eth->d_addr),&(priv->nat_eth)) &&
			 ip->dst_addr == priv->nat_ip &&
			 *dst_port    == entry->nat_port &&
			 ip->src_addr == entry->out_ip &&
			 *src_port    == entry->out_port ) ) {
		    // if flow doesn't exist, don't do anything (continue)
		    continue;
		  }
		  // rewrite the dest eth (nat_eth) to entry->in_eth
		  eth->d_addr = entry->in_eth;
		  // rewrite the dest ip (nat_ip) to entry->in_ip
		  ip->dst_addr = entry->in_ip;
		  // rewrite the dest port (entry->nat_port) to entry->in_port
		  *dst_port = entry->in_port;
		  // update all checksums		 
		}
		else {
		  // we should report an error condition, but for now just skip the packet
		  continue;
		}		
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
