#include "ndpi_utils.h"
#include "ndpi_protocols.h"
#include<linux/kernel.h>



#ifdef NDPI_PROTOCOL_PTT
static void ndpi_int_ptt_add_connection(struct ndpi_detection_module_struct
                                           *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PTT, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_ptt(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;
  u_int32_t ip_sa=0,ip_da=0;

  NDPI_LOG(NDPI_PROTOCOL_ORACLE, ndpi_struct, NDPI_LOG_DEBUG, "search for ORACLE.\n");
  pr_info("search ptt 1\n");
  pr_info("sa %lu ",ntohl(packet->iph->saddr));
  pr_info("da %lu\n",ntohl(packet->iph->daddr));
  if(packet->tcp != NULL){
        pr_info("search ptt 2\n");
	if(((ntohl(packet->iph->saddr) & 0xFFFFFF00)==0x8C70AC00)||((ntohl(packet->iph->daddr) & 0xFFFFFF00)==0x8C70AC00)){
		ndpi_int_ptt_add_connection(ndpi_struct, flow);
		pr_info("search ptt 3\n");
		return ;
	}
  }
  else{
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_PTT);
  }

}
#endif

