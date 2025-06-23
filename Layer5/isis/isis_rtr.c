#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_pkt.h"
#include "isis_intf.h"
#include "layer5.h"
#include "isis_const.h"

bool isis_is_protocol_enable_on_node(node_t *node)
{
    if(ISIS_NODE_INFO(node))
        return true;
    
    return false;
}

void isis_show_node_protocol_state(node_t *node)
{
    interface_t *intf;
    printf("ISIS Protocol : %s\n", isis_is_protocol_enable_on_node(node) ? "Enable" : "Disable");

    ITERATE_NODE_INTERFACES_BEGIN(node, intf){

        if(intf){
            printf("%s : %s\n", intf->if_name, isis_is_protocol_enable_on_node_intf(intf) ? "Enable" : "Disable");
        }
        
    }ITERATE_NODE_INTERFACES_END(node, intf);
}

void isis_init(node_t *node)
{
    isis_node_info_t *node_info = NULL;

    node_info = ISIS_NODE_INFO(node);
    if(node_info)
        return;
    node_info = calloc(1, sizeof(isis_node_info_t));
    node->node_nw_prop.isis_node_info = node_info;
    printf("%s: ISIS Protocol initialized at node level\n", __FUNCTION__);
    //node_info->seq_no = 0;

    tcp_stack_register_l2_pkt_trap_rule(node, isis_pkt_trap_rule, isis_pkt_receive);
}

void isis_de_init(node_t *node)
{
    isis_node_info_t *node_info = NULL;

    node_info = ISIS_NODE_INFO(node);
    if(node_info){
        free(node_info);
        node->node_nw_prop.isis_node_info = node_info;
    }
    tcp_stack_de_register_l2_pkt_trap_rule(node, isis_pkt_trap_rule, isis_pkt_receive);
}

void isis_one_time_registration(void)
{
    nfc_intf_register_for_events(isis_interface_updates);
    nfc_register_for_pkt_tracing(ISIS_ETH_PKT_TYPE, isis_print_pkt);
}