#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_pkt.h"
#include "isis_intf.h"
#include "layer5.h"
#include "isis_const.h"
#include "isis_lsdb.h"

static void isis_node_cancel_all_queued_jobs(node_t *node)
{
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if(node_info->lsp_pkt_gen_task){
        task_cancel_job(node_info->lsp_pkt_gen_task);
        node_info->lsp_pkt_gen_task = NULL;
    }
}

bool isis_is_protocol_enable_on_node(node_t *node)
{
    if(ISIS_NODE_INFO(node))
        return true;
    
    return false;
}

void isis_show_node_protocol_state(node_t *node)
{
    interface_t *intf;
    isis_node_info_t *isis_node_info;
    printf("ISIS Protocol : %s\n", isis_is_protocol_enable_on_node(node) ? "Enable" : "Disable");

    if(!isis_is_protocol_enable_on_node(node))
        return;
    
    isis_node_info = ISIS_NODE_INFO(node);
    printf("Adjacency up count: %u\n", isis_node_info->adj_up_count);

    ITERATE_NODE_INTERFACES_BEGIN(node, intf){

        if(!isis_node_intf_is_enable(intf))
            continue;
        isis_show_interface_protocol_state(intf);
        
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
    node->node_nw_prop.isis_node_info->layer2_mapping = false;
    printf("%s: ISIS Protocol initialized at node level\n", __FUNCTION__);
    node_info->seq_no = 0;

    tcp_stack_register_l2_pkt_trap_rule(node, isis_pkt_trap_rule, isis_pkt_receive);
    isis_schedule_lsp_pkt_generation(node);
}

void isis_de_init(node_t *node)
{
    isis_node_info_t *node_info = NULL;

    node_info = ISIS_NODE_INFO(node);
    if(node_info){
        free(node_info);
        node->node_nw_prop.isis_node_info = node_info;
    }
    isis_node_cancel_all_queued_jobs(node);
    tcp_stack_de_register_l2_pkt_trap_rule(node, isis_pkt_trap_rule, isis_pkt_receive);
}

void isis_one_time_registration(void)
{
    /* register for notification to change in interface properties/configuration */
    nfc_intf_register_for_events(isis_interface_updates);
    /* register for notification to isis trace pkts */
    nfc_register_for_pkt_tracing(ISIS_ETH_PKT_TYPE, isis_print_pkt);
}

