#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_const.h"

bool isis_pkt_trap_rule(char *pkt, size_t pkt_size){

    ethernet_frame_t *eth_pkt = (ethernet_frame_t *)pkt;

    return (eth_pkt->type == ISIS_ETH_PKT_TYPE);
}

void isis_pkt_receive(void *arg, size_t arg_size)
{

}

