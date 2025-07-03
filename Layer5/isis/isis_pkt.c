#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_intf.h"
#include "isis_rtr.h"
#include "isis_adjacency.h"
#include "layer5.h"


static uint32_t isis_print_hello_pkt(byte *buff, isis_pkt_hdr_t *hello_pkt_hdr, uint32_t pkt_size)
{
    uint32_t rc = 0;
    char *ip_addr_str;
    byte tlv_type;
    byte tlv_len;
    byte *tlv_value = NULL;

    byte *hello_tlv_buffer = (byte *)(hello_pkt_hdr + 1U);
    uint32_t hello_tlv_buffer_size = pkt_size - sizeof(isis_pkt_hdr_t);

    rc = sprintf(buff, "ISIS_PTP_HELLO_PKT_TYPE : ");

    ITERATE_TLV_BEGIN(hello_tlv_buffer , tlv_type, tlv_len, tlv_value, hello_tlv_buffer_size){

        switch(tlv_type){
            case ISIS_TLV_IF_INDEX:
                rc += sprintf(buff + rc, "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)(tlv_value));
            break;
            case ISIS_TLV_HOSTNAME:
                rc += sprintf(buff + rc, "%d %d %s :: ", tlv_type, tlv_len, tlv_value);
                break;
            case ISIS_TLV_RTR_ID:
            case ISIS_TLV_IF_IP:
                ip_addr_str = tcp_ip_convert_ip_n_to_p(*(uint32_t *)tlv_value, 0);
                rc += sprintf(buff + rc, "%d %d %s :: ", tlv_type, tlv_len, ip_addr_str);
                break;
            case ISIS_TLV_HOLD_TIME:
                rc += sprintf(buff + rc, "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)tlv_value);
                break;
            case ISIS_TLV_METRIC_VAL:
                rc += sprintf(buff + rc, "%d %d %u :: ", tlv_type, tlv_len, *(uint32_t *)tlv_value);
                break;
            case ISIS_TLV_IF_MAC:
                rc += sprintf(buff + rc, "%d %d %02x:%02x:%02x:%02x:%02x:%02x :: ",
                     tlv_type, tlv_len, tlv_value[0], tlv_value[1], tlv_value[2],
                     tlv_value[3], tlv_value[4], tlv_value[5]);
                break;    
            default:    ;
        }

    } ITERATE_TLV_END(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, hello_tlv_buffer_size)
    
    rc -= strlen(" :: ");
    return rc;
}

static uint32_t isis_print_lsp_pkt(byte *buff, isis_pkt_hdr_t *hello_pkt_hdr, uint32_t pkt_size)
{

}

bool isis_pkt_trap_rule(char *pkt, size_t pkt_size){

    ethernet_frame_t *eth_pkt = (ethernet_frame_t *)pkt;

    return (eth_pkt->type == ISIS_ETH_PKT_TYPE);
}

static void isis_process_hello_pkt(node_t *node, interface_t *iif, ethernet_frame_t *hello_eth_hdr, size_t pkt_size)
{
    char if_ip_addr_str[16];

    /* Pkt robustness check */
    /* 1. Reject the pkt if isis is not enabled in the interface */
    if(!isis_node_intf_is_enable(iif)){
        printf("%s: Error - ISIS Protocol not enabled for the interface\n", __FUNCTION__);
        return;
    }

    /* 2. Check if interface is UP and has an IP address */
    if(!isis_interface_qualify_to_send_hellos(iif)){
        printf("%s: Error - Interface not UP or NO IP address configured\n", __FUNCTION__);
        return;
    }

    /* 3. Reject if the dest MAC is not a broadcast address */
    if(!IS_MAC_BROADCAST_ADDR(hello_eth_hdr->dst_mac.mac_addr)){
        printf("%s: Error - Bad hello Packet, Dst MAC not broadcast type\n", __FUNCTION__);
        assert(0);
        goto bad_hello;
    }

    /* 4. Check if the hello pkt has the TLVs */
    isis_pkt_hdr_t *hello_pkt_hdr = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);
    byte *hello_tlv_buffer =  (byte *)(hello_pkt_hdr + 1U);
    size_t tlv_buff_size = pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD - sizeof(isis_pkt_hdr_t);

    uint8_t intf_ip_len;
    uint32_t *if_ip_addr_int = (uint32_t *)tlv_buffer_get_particular_tlv(hello_tlv_buffer, tlv_buff_size, ISIS_TLV_IF_IP, &intf_ip_len);
    if(!if_ip_addr_int){
        printf("%s: Error - Bad hello Packet, doesn't have TLVs\n", __FUNCTION__);
        assert(0);
        goto bad_hello;
    }

    /* 5. Reject the pkt if neighbour node's interface IP doesn't fall on the same subnet */
    char *ip_str = tcp_ip_convert_ip_n_to_p(*if_ip_addr_int, 0);
    strncpy(if_ip_addr_str, ip_str, 16U); /* observed stack corruption without this */
    printf("%s: Hello Pkt received on intf with IP %s/%d from interface with IP %s\n", __FUNCTION__, IF_IP(iif), IF_MASK(iif), if_ip_addr_str);
    if(!is_same_subnet(IF_IP(iif), IF_MASK(iif), if_ip_addr_str)){
        printf("%s: Error - Hello Pkt from different subnet\n", __FUNCTION__);
        assert(0);
        goto bad_hello;
    }

    /* 6. Accept the pkt, create adjacency */
    isis_update_interface_adjacency_from_hello(iif, hello_tlv_buffer, tlv_buff_size);
    return;

    bad_hello:
        printf("%s: Hello Pkt rejected on Node %s , interface %s\n", __FUNCTION__, node->node_name, iif->if_name);
        ISIS_INTF_INCREMENT_STATS(iif, bad_hello_pkt_recvd);
}

static void isis_process_lsp_pkt(node_t *node, interface_t *iif, ethernet_frame_t *lsp_eth_hdr, size_t pkt_size)
{

}

void isis_pkt_receive(void *arg, size_t arg_size)
{
    pkt_notif_data_t *pkt_notif_data = (pkt_notif_data_t *)arg;
    node_t *node = pkt_notif_data->recv_node;
    interface_t *iif = pkt_notif_data->recv_interface;
    ethernet_frame_t *eth_hdr = (ethernet_frame_t *)pkt_notif_data->pkt;
    uint32_t pkt_size = pkt_notif_data->pkt_size;

    if(!isis_is_protocol_enable_on_node(node)){
        return;
    }

    isis_pkt_hdr_t *isis_pkt_hdr = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_hdr);
    switch(isis_pkt_hdr->isis_pkt_type){
        case ISIS_PTP_HELLO_PKT_TYPE:     
            printf("%s: ISIS - Hello pkt received\n",__FUNCTION__);
            isis_process_hello_pkt(node, iif, eth_hdr, pkt_size);
            break;
        case ISIS_LSP_PKT_TYPE:
            printf("%s: ISIS - LSP pkt received\n", __FUNCTION__);
            isis_process_lsp_pkt(node, iif, eth_hdr, pkt_size);
            break;
        default:
            ;
    }
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
    hello_pkt_hdr->rtr_id = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDRESS(intf->att_node));
    hello_pkt_hdr->seq_no = 0; /* Ignored for now */
    hello_pkt_hdr->flags = 0;  /* ignored for now */

    temp = (char *)(hello_pkt_hdr + 1U); // could also be written as (char *)hello_pkt_hdr + sizeof(hello_pkt_hdr_t)
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOSTNAME, NODE_NAME_SIZE, node->node_name);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_RTR_ID, 4U, (byte *)&hello_pkt_hdr->rtr_id);

    uint32_t ip_addr_int = tcp_ip_convert_ip_p_to_n(IF_IP(intf));
    uint32_t hold_time = ISIS_INTF_HELLO_INTERVAL(intf) * ISIS_HOLD_TIME_FACTOR;
    uint32_t cost = ISIS_INTF_COST(intf);

    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_IP, sizeof(uint32_t), (byte *)&ip_addr_int);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_INDEX, sizeof(uint32_t), (byte *)&IF_INDEX(intf));
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_HOLD_TIME, sizeof(uint32_t), (byte *)&hold_time);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_METRIC_VAL, sizeof(uint32_t), (byte *)&cost);
    temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_MAC, sizeof(mac_add_t), IF_MAC(intf));
#if ISIS_ENABLE_AUTH      
    if(ISIS_INTF_IS_AUTH_ENABLED(intf))
        temp = tlv_buffer_insert_tlv(temp, ISIS_TLV_IF_AUTH , 32, (byte *)&ISIS_INTF_AUTH_PASSCODE(intf));
#endif
    SET_COMMON_ETH_FCS(hello_eth_hdr, eth_pkt_paylod_size, 0);
    return (byte *)hello_eth_hdr;
}

void isis_print_pkt(void *arg, size_t arg_size)
{
    pkt_info_t *pkt_info;
    pkt_info = (pkt_info_t *)arg;
    byte *buff = pkt_info->pkt_print_buffer;
    size_t pkt_size = pkt_info->pkt_size;

    isis_pkt_hdr_t *pkt_hdr = (isis_pkt_hdr_t *)(pkt_info->pkt);
    pkt_info->bytes_written = 0;
    isis_pkt_type_t pkt_type = pkt_hdr->isis_pkt_type;

    switch(pkt_type)
    {
        case ISIS_PTP_HELLO_PKT_TYPE:
        {
            pkt_info->bytes_written += isis_print_hello_pkt(buff, pkt_hdr, pkt_size);
            printf("%s reached\n",__FUNCTION__);
            break;
        }
        case ISIS_LSP_PKT_TYPE:
        {
            pkt_info->bytes_written += isis_print_lsp_pkt(buff, pkt_hdr, pkt_size);
        }
        default:
            ;
    }
}

void isis_create_fresh_lsp_pkt(node_t *node)
{
    /* Steps:
     *  1. Calculate the total size of the new LSP Packet
     *  2. Allocate buffer (using malloc) for the new LSP packet
     *  3. Populate the contents of the new LSP pkt
     *  4. Discard the old LPS pkt
     *  5. Cache the new LSP pkt
     */
    /* Step #1 */
    size_t lsp_size_estimate;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if(!node)
        return;
        
    lsp_size_estimate += ETH_HDR_SIZE_EXCL_PAYLOAD;                 /* ETH header size */
    lsp_size_estimate += sizeof(isis_pkt_hdr_t);                    /* ISIS Pkt header size */
    lsp_size_estimate += TLV_OVERHEAD_SIZE + NODE_NAME_SIZE;        /* size of Hostname TLV Type, TLV len and Hostname */
    lsp_size_estimate += isis_size_to_encode_all_nbr_tlv(node);     /* size for all TLVs (TLV22) and sub TLVs */

    if(lsp_size_estimate > MAX_PACKET_BUFFER_SIZE)
        return;

    /* Step #2 */
    /* Create memory for whole MAX_PACKET buffer size and then shift right so that new headers can be inserted (if required)*/
    ethernet_frame_t *eth_pkt = tcp_ip_get_new_pkt_buffer(lsp_size_estimate);
    memset(eth_pkt->src_mac.mac_addr, 0, sizeof(mac_add_t));        /* sourec MAC should be empty */
    layer2_fill_with_broadcast_mac(eth_pkt->dst_mac.mac_addr);      /* destination MAC should be broadcast */
    eth_pkt->type = ISIS_ETH_PKT_TYPE;

    /* Step #3 */
    isis_pkt_hdr_t *isis_pkt = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_pkt);
    isis_pkt->isis_pkt_type = ISIS_LSP_PKT_TYPE;
    isis_pkt->seq_no++;
    isis_pkt->rtr_id = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDRESS(node));

    byte *lsp_tlv_buffer = (byte *)(isis_pkt + 1U);
    lsp_tlv_buffer = tlv_buffer_insert_tlv(lsp_tlv_buffer, ISIS_TLV_HOSTNAME, NODE_NAME_SIZE, node->node_name);
    lsp_tlv_buffer = isis_encode_all_nbr_tlvs(node, lsp_tlv_buffer);

    if(node_info->self_lsp_pkt){
        tcp_ip_free_pkt_buffer(node_info->self_lsp_pkt->pkt, lsp_size_estimate);
        free(node_info->self_lsp_pkt);
        node_info->self_lsp_pkt = NULL;
    }

    /* Step #4 */
    node_info->self_lsp_pkt = calloc(1, sizeof(isis_lsp_pkt_t));
    node_info->self_lsp_pkt->pkt = (byte *)eth_pkt;
    node_info->self_lsp_pkt->pkt_size = lsp_size_estimate;
}

uint32_t *isis_get_lsp_pkt_rtr_id(isis_lsp_pkt_t *lsp_pkt)
{
    ethernet_frame_t *eth_pkt = (ethernet_frame_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *isis_pkt = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_pkt);
    return (uint32_t *)&isis_pkt->rtr_id;
}

uint32_t *isis_get_lsp_pkt_seq_no(isis_lsp_pkt_t *lsp_pkt)
{
    ethernet_frame_t *eth_pkt = (ethernet_frame_t *)lsp_pkt->pkt;
    isis_pkt_hdr_t *isis_pkt = (isis_pkt_hdr_t *)GET_ETHERNET_HDR_PAYLOAD(eth_pkt);
    return (uint32_t *)&isis_pkt->seq_no;
}