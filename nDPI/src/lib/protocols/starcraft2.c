#include "ndpi_utils.h"
#include "ndpi_protocols.h"
#include<linux/kernel.h>

#ifdef NDPI_PROTOCOL_STARCRAFT2
static void ndpi_int_starcraft2_add_connection(struct ndpi_detection_module_struct
                                           *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_STARCRAFT2, NDPI_REAL_PROTOCOL);
}
#if !defined(WIN32)
static inline
#else
__forceinline static
#endif
u_int8_t ndpi_int_is_sc2_port(const u_int16_t port)
{
  if (port == htons(3724) || port == htons(6112) || port == htons(6113) ||
        port == htons(6114) || port == htons(1119)) {
	    return 1;
	      }
	        return 0;
}
void ndpi_search_starcraft2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	NDPI_LOG(NDPI_PROTOCOL_WORLDOFWARCRAFT, ndpi_struct, NDPI_LOG_DEBUG, "Search SC2.\n");
	if (packet->tcp != NULL){
		if ((packet->payload_packet_len > NDPI_STATICSTRING_LEN("POST /") &&
			memcmp(packet->payload, "POST /", NDPI_STATICSTRING_LEN("POST /")) == 0)||
			(packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /") &&
			memcmp(packet->payload, "GET /", NDPI_STATICSTRING_LEN("GET /")) == 0)){
				ndpi_parse_packet_line_info(ndpi_struct, flow);
				if(packet->payload[0]=='G'){
					if(packet->payload[5]=='s'&&packet->payload[6]=='c'&&packet->payload[7]=='2'){
						if(packet->host_line.ptr!=NULL
						&&packet->host_line.len== NDPI_STATICSTRING_LEN("dist.blizzard.com.edgesuite.net")&&
						memcmp(packet->host_line.ptr,"dist.blizzard.com.edgesuite.net",
						NDPI_STATICSTRING_LEN("dist.blizzard.com.edgesuite.net"))==0){
							ndpi_int_starcraft2_add_connection(ndpi_struct, flow);
							return ;
						}
					}
				}
				if (packet->user_agent_line.ptr != NULL &&
					  packet->user_agent_line.len == NDPI_STATICSTRING_LEN("Battle.net Web Client") &&
					  	  memcmp(packet->user_agent_line.ptr, "Battle.net Web Client",
						  		 NDPI_STATICSTRING_LEN("Battle.net Web Client")) == 0){
				
					ndpi_int_starcraft2_add_connection(ndpi_struct, flow);
					return ;
				}
		
		}
		if(ndpi_int_is_sc2_port(packet->tcp->source)||ndpi_int_is_sc2_port(packet->tcp->dest)){
			if(((ntohl(packet->iph->saddr)&0xFFFFFFFF)==0xcb427633)||((ntohl(packet->iph->daddr) & 0xFFFFFFFF)==0xcb427633)){
				ndpi_int_starcraft2_add_connection(ndpi_struct, flow);
				return;
			}
		}
		if(packet->payload[0]=='E'&&packet->payload[37]=='C'&&packet->payload[38]=='n'){
			//login special packet
			if(ndpi_int_is_sc2_port(packet->tcp->source)||ndpi_int_is_sc2_port(packet->tcp->dest)){
				ndpi_int_starcraft2_add_connection(ndpi_struct, flow);
				return ;
			}
		}
	}
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_STARCRAFT2);
}
#endif
