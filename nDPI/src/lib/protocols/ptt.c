#include "ndpi_utils.h"
#include "ndpi_protocols.h"
#include<linux/kernel.h>



#ifdef NDPI_PROTOCOL_PTT
static void ndpi_int_ptt_add_connection(struct ndpi_detection_module_struct
                                           *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_PTT, NDPI_REAL_PROTOCOL);
}
void ndpi_search_ptt(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;
  register u_int16_t ii;

  NDPI_LOG(NDPI_PROTOCOL_ORACLE, ndpi_struct, NDPI_LOG_DEBUG, "search for ptt.\n");
  if(packet->tcp != NULL){
  	sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
	for (ii = 0;  ii < packet->payload_packet_len ; ++ii){
		if(packet->payload[ii]=='P'){
			if(packet->payload[ii+1]=='T'){
			 	if(packet->payload[ii+2]=='T'&&(sport==23||dport==23)){
			   		ndpi_int_ptt_add_connection(ndpi_struct, flow); 
			   		return;
			 	}
			
			}
		}
	
	}
	if(((ntohl(packet->iph->saddr) & 0xFFFFFF00)==0x8C70AC00)||((ntohl(packet->iph->daddr) & 0xFFFFFF00)==0x8C70AC00)){
		if(sport==23||dport==23){
			ndpi_int_ptt_add_connection(ndpi_struct, flow);			
			return ;
		}
		
 	}
  	else{
		NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_PTT);
  	}
  }
}
#endif

