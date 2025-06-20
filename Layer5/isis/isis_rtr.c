#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_pkt.h"

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