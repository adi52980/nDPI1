#include "ndpi_utils.h"
#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_JUSTIN_TWITCH
static void ndpi_int_justin_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_JUSTIN_TWITCH, NDPI_REAL_PROTOCOL);
}
void ndpi_search_justin_twitch(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	register u_int16_t ii;
	u_int16_t dport=0,sport=0;
	if(packet->tcp!=NULL){
		sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
		if(sport==1935||dport==1935){
			ndpi_int_justin_add_connection(ndpi_struct, flow);
			return ;
		}
	}
	for(ii=0;ii<packet->payload_packet_len;	++ii){
		if(packet->payload[ii]=='t'){
			if(memcmp(&packet->payload[ii + 1], "witch.tv", 8)==0){
				NDPI_LOG(NDPI_PROTOCOL_JUSTIN_TWITCH, ndpi_struct, NDPI_LOG_DEBUG, "twitch  detected.\n");
				ndpi_int_justin_add_connection(ndpi_struct, flow);
				return ;
			}
		}
		if(packet->payload[ii]=='a'){
			if(memcmp(&packet->payload[ii + 1], "pi.twitch.tv",12)==0){
				NDPI_LOG(NDPI_PROTOCOL_JUSTIN_TWITCH, ndpi_struct, NDPI_LOG_DEBUG, "twitch  detected.\n");
				ndpi_int_justin_add_connection(ndpi_struct, flow);
				return ;
			}
		}
		if(packet->payload[ii]=='H'){
			if(memcmp(&packet->payload[ii + 1], "ost:www.twitch.tv",17)==0){
				NDPI_LOG(NDPI_PROTOCOL_JUSTIN_TWITCH, ndpi_struct, NDPI_LOG_DEBUG, "twitch  detected.\n");
				ndpi_int_justin_add_connection(ndpi_struct, flow);
				return ;
			}
			
		}
	}
	
	for (ii = 0;  ii < packet->payload_packet_len ; ++ii){
		if(packet->payload[ii]=='j'){
			if (memcmp(&packet->payload[ii + 1], "ustin.tv/", 9)==0){
				NDPI_LOG(NDPI_PROTOCOL_JUSTIN_TWITCH, ndpi_struct, NDPI_LOG_DEBUG, "justin  detected.\n");
				ndpi_int_justin_add_connection(ndpi_struct, flow);
				return ;
			}
		}
	}
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_JUSTIN_TWITCH);
}
#endif
