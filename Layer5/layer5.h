#ifndef __LAYER5_H__
#define __LYAER5_H__

#include "../tcpip_notif.h"

typedef struct node_ node_t;
typedef struct interface_ interface_t;

typedef struct pkt_notif_data_
{
    node_t *recv_node;
    interface_t *recv_interface;
    char *pkt;
    uint32_t pkt_size;
	hdr_type_t hdr_code;
	int8_t return_code;
}pkt_notif_data_t;

#if 0
void promote_pkt_to_layer5(node_t *node, interface_t *recv_intf, char *l5_hdr, uint32_t pkt_size, uint32_t L5_protocol, uint32_t flags);

void tcp_app_register_l2_protocol_interest(uint32_t L5_protocol, nfc_app_cb app_layer_cb);

void tcp_app_register_l3_protocol_interest(uint32_t L5_protocol, nfc_app_cb app_layer_cb);
#endif

void tcp_stack_register_l2_pkt_trap_rule(node_t *node, nfc_pkt_trap pkt_trap_cb, nfc_app_cb app_cb);
void tcp_stack_de_register_l2_pkt_trap_rule(node_t *node, nfc_pkt_trap pkt_trap_cb, nfc_app_cb app_cb);

#endif