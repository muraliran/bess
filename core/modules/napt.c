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
#define MAX_MAP_ENTRIES 10
#define NAT_START_PORT  44001

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


static int add_entry(struct napt_priv *priv,
		     uint32_t in_ip,
		     uint16_t in_port,
		     uint32_t out_ip,
		     uint16_t out_port)
{
  if (priv->num_entries == MAX_MAP_ENTRIES)
    return -1;
  
  priv->entry[priv->num_entries].in_ip    = in_ip;
  priv->entry[priv->num_entries].out_ip   = out_ip;
  priv->entry[priv->num_entries].in_port  = in_port;
  priv->entry[priv->num_entries].out_port = out_port;
  priv->entry[priv->num_entries].nat_port = htons(NAT_START_PORT +
						  priv->num_entries);
  priv->num_entries++;
  return priv->num_entries - 1;
}


static struct snobj *napt_init(struct module *m, struct snobj *arg)
{
	struct napt_priv *priv = get_priv(m);

	log_info("NAPT:napt_init\n");
 	
	// hardcode the nat IP
	priv->nat_ip = htonl(IPv4(192, 168, 10, 4));
	priv->ether_type_ipv4 = htons(ETHER_TYPE_IPv4);
	
	// Set the nat ip based on the input arg
	//	if (arg) {
	//  char *ip_str = snobj_eval_str(arg, "ip");
	//  char *octet;
	//  char *left;
	//  octet = strtok(ip_str,".");
	//  
	//  }
	  
	return NULL;
}


static int outbound_flow_match(struct napt_mapping_entry *entry,
			       struct ipv4_hdr *ip,
			       uint16_t *src_port,
			       uint16_t *dst_port)
{
  return ( ip->src_addr == entry->in_ip   &&
	   *src_port    == entry->in_port &&
	   ip->dst_addr == entry->out_ip  &&
	   *dst_port    == entry->out_port );
}


static int inbound_flow_match(struct napt_priv *priv,
			      struct napt_mapping_entry *entry,
			      struct ipv4_hdr *ip,
			      uint16_t *src_port,
			      uint16_t *dst_port)
{
  return ( ip->dst_addr == priv->nat_ip &&
	   *dst_port    == entry->nat_port &&
	   ip->src_addr == entry->out_ip &&
	   *src_port    == entry->out_port );
}


static int find_matching_entry(struct napt_priv *priv,
			       gate_idx_t direction,
			       struct ipv4_hdr *ip,
			       uint16_t *src_port,
			       uint16_t *dst_port)
{
  struct napt_mapping_entry *entry;
  for(int i=0; i<priv->num_entries; i++) {
    entry = &(priv->entry[i]);
    if (direction == OUTBOUND) {
      if (outbound_flow_match(entry, ip, src_port, dst_port))
	return i;
    }
    else if (direction == INBOUND) {
      if (inbound_flow_match(priv, entry, ip, src_port, dst_port))
	return i;
    }
    else
      return -1;
  }
  return -1;
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
	struct napt_mapping_entry *entry;
	
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

		int ind = -1;
		if (direction[i] == OUTBOUND) {
		  log_info("OUTBOUND\n");
		  // check for an existing entry
		  ind = find_matching_entry(priv, direction[i], ip, src_port, dst_port); 
		  if (ind < 0)
		    ind = add_entry(priv,
				    ip->src_addr,
				    *src_port,
				    ip->dst_addr,
				    *dst_port);
				    
		  if (ind >= 0) {
		    entry = &(priv->entry[ind]);
		    // rewrite source ip:port
		    ip->src_addr = priv->nat_ip;
		    *src_port = entry->nat_port;
		    log_info("source ip:port rewritten\n");
		  }
		  else{
		    log_info("MAX ENTRIES ALREADY USED\n");
		    continue;
		  }
		}
		else if (direction[i] == INBOUND) {
		  log_info("INBOUND\n");
		  // check for an existing entry in priv->map
		  ind = find_matching_entry(priv, direction[i], ip, src_port, dst_port); 
		  if (ind >= 0) {
		    entry = &(priv->entry[ind]);
		    // rewrite destination ip/port
		    ip->dst_addr = entry->in_ip;
		    *dst_port = entry->in_port;
		    log_info("destination ip:port rewritten\n");
		  }
		  else{
		    // packet should be deleted
		    log_info("ENTRY NOT FOUND\n");
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
