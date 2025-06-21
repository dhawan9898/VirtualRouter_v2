#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_intf.h"
#include "isis_rtr.h"

bool isis_pkt_trap_rule(char *pkt, size_t pkt_size){

    ethernet_frame_t *eth_pkt = (ethernet_frame_t *)pkt;

    return (eth_pkt->type == ISIS_ETH_PKT_TYPE);
}

void isis_pkt_receive(void *arg, size_t arg_size)
{

}

byte *isis_prepare_hello_pkt(interface_t *intf, size_t *hello_pkt_size)
{
    byte *temp;
    node_t *node = intf->att_node;
    isis_pkt_hdr_t *hello_pkt_hdr;
    uint32_t eth_pkt_paylod_size = sizeof(isis_pkt_hdr_t) +     /* size of isis header */
                                   (TLV_OVERHEAD_SIZE * 6U) +   /* size for 6 TLV's Type and size fields */
                                   NODE_NAME_SIZE +             /* size of the node name */
                                   4u + 4U +                    /* size of two IPs - Node's Lo address and Intf's IP address */
                                   4u + 4U + 4U +               /* size of interface index + hold time + cost */
                                   6U;                          /* Size of interface mAC address */

    *hello_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + eth_pkt_paylod_size;
    ethernet_frame_t *hello_eth_hdr = (ethernet_frame_t *)tcp_ip_get_new_pkt_buffer(*hello_pkt_size);
    layer2_fill_with_broadcast_mac(hello_eth_hdr->dst_mac.mac_addr);
    memset(hello_eth_hdr->src_mac.mac_addr, 0, sizeof(mac_add_t));
    hello_eth_hdr->type = ISIS_ETH_PKT_TYPE;

    hello_pkt_hdr = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);
    hello_pkt_hdr->isis_pkt_type = ISIS_PTP_HELLO_PKT_TYPE;
    hello_pkt_hdr->rtr_id = tcp_ip_covert_ip_p_to_n(NODE_LO_ADDRESS(intf->att_node));
    hello_pkt_hdr->seq_no = 0; /* Ignored for now */
    hello_pkt_hdr->flags = 0;  /* ignored for now */

    temp = (char *)(hello_pkt_hdr + 1U); // could also be written as (char *)hello_pkt_hdr + sizeof(hello_pkt_hdr_t)
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOSTNAME, NODE_NAME_SIZE, node->node_name);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_RTR_ID, 4U, (byte *)&hello_pkt_hdr->rtr_id);

    uint32_t ip_addr_int = tcp_ip_covert_ip_p_to_n(IF_IP(intf));
    uint32_t hold_time = ISIS_INTF_HELLO_INTERVAL(intf) * ISIS_HOLD_TIME_FACTOR;
    uint32_t cost = ISIS_INTF_COST(intf);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_IP, sizeof(uint32_t), (byte *)&ip_addr_int);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_INDEX, sizeof(uint32_t), (byte *)&IF_INDEX(intf));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOLD_TIME, sizeof(uint32_t), (byte *)&hold_time);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_METRIC_VAL, sizeof(uint32_t), (byte *)&cost);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_MAC, sizeof(mac_add_t), IF_MAC(intf));

    SET_COMMON_ETH_FCS(hello_eth_hdr, eth_pkt_paylod_size, 0);
    return (byte *)hello_eth_hdr;
}

