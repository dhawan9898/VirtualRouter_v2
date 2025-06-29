#include "../../tcp_public.h"
#include "isis_adjacency.h"
#include "isis_intf.h"
#include "isis_rtr.h"
#include "isis_const.h"
#include "isis_lsdb.h"
#include "isis_flood.h"
#include "isis_l2map.h"

static void isis_timer_expire_delete_adjacency_cb(void *arg, size_t arg_size)
{
    if(!arg)
        return;
    isis_adjacency_t *adjacency = (isis_adjacency_t *)arg;
    interface_t *intf = adjacency->intf;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    intf_info->adjacency = NULL;
    de_register_app_event(adjacency->delete_timer);
    adjacency->delete_timer = NULL;

    assert(!adjacency->expiry_timer);
    free(adjacency);
}

static void isis_adjacency_start_delete_timer(isis_adjacency_t *adjacency)
{
    if(adjacency->delete_timer)
        return;
    adjacency->delete_timer = register_app_event(node_get_timer_instance(adjacency->intf->att_node),
                                                        isis_timer_expire_delete_adjacency_cb,
                                                        (void *)adjacency, sizeof(isis_adjacency_t),
                                                        ISIS_ADJ_DEFAULT_DELETE_TIME, 0);

}

static void isis_adjacency_stop_delete_timer(isis_adjacency_t *adjacency)
{
    if(!adjacency->delete_timer)
        return;
    de_register_app_event(adjacency->delete_timer);
    adjacency->delete_timer = NULL;
}

static void isis_timer_expire_down_adjacency_cb(void *arg, size_t arg_size)
{
    if(!arg)
        return;
    isis_adjacency_t *adjacency = (isis_adjacency_t *)arg;
    de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;

    isis_change_adjacency_state(adjacency, ISIS_ADJ_STATE_DOWN);
}

static void isis_adjacency_start_expiry_timer(isis_adjacency_t *adjacency)
{
    if(adjacency->expiry_timer)
        return;
    adjacency->expiry_timer = register_app_event(node_get_timer_instance(adjacency->intf->att_node),
                                                    isis_timer_expire_down_adjacency_cb,
                                                    (void *)adjacency, sizeof(isis_adjacency_t),
                                                    adjacency->hold_time, 0);
}

static void isis_adjacency_stop_expiry_timer(isis_adjacency_t *adjacency)
{
    if(!adjacency->expiry_timer)
        return;
    de_register_app_event(adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
}

static void isis_adjacency_refresh_expiry_timer(isis_adjacency_t *adjacency)
{
    assert(adjacency->expiry_timer);
    reschedule_timer(adjacency->expiry_timer, adjacency->hold_time, 0); //To revisit
}

void isis_show_adjacency( isis_adjacency_t *adjacency, uint8_t tab_spaces) {

    char *ip_addr_str;

    PRINT_TABS(tab_spaces);
    ip_addr_str = tcp_ip_convert_ip_n_to_p (adjacency->nbr_rtr_id, 0);
    printf("Nbr : %s(%s)\n", adjacency->nbr_name, ip_addr_str);

    PRINT_TABS(tab_spaces);
    ip_addr_str = tcp_ip_convert_ip_n_to_p( adjacency->nbr_intf_ip, 0);
    printf("Nbr intf ip : %s  ifindex : %u\n",
        ip_addr_str,
        adjacency->remote_if_index);
        
    PRINT_TABS(tab_spaces);
    printf("Nbr Mac Addr : %02x:%02x:%02x:%02x:%02x:%02x\n", 
            adjacency->nbr_mac.mac_addr[0], 
            adjacency->nbr_mac.mac_addr[1], 
            adjacency->nbr_mac.mac_addr[2], 
            adjacency->nbr_mac.mac_addr[3], 
            adjacency->nbr_mac.mac_addr[4], 
            adjacency->nbr_mac.mac_addr[5]);

    PRINT_TABS(tab_spaces);
    printf("State : %s   HT : %u sec   Cost : %u\n",
        isis_adj_state_str(adjacency->adj_state),
        adjacency->hold_time,
        adjacency->cost);

    PRINT_TABS(tab_spaces);

    if (adjacency->expiry_timer) {
        printf("Expiry Timer Remaining : %u msec\n",
                wt_get_remaining_time(adjacency->expiry_timer));
    }
    else {
        printf("Expiry Timer : Nil\n");
    }

    PRINT_TABS(tab_spaces);

    if (adjacency->delete_timer) {
         printf("Delete Timer Remaining : %u msec\n",
            wt_get_remaining_time(adjacency->delete_timer));
    }
    else {
        printf("Delete Timer : Nil\n");
    }

    if (adjacency->adj_state == ISIS_ADJ_STATE_UP) {

        PRINT_TABS(tab_spaces);
        printf("Up Time : %s\n", hrs_min_sec_format(
                (unsigned int)difftime(time(NULL), adjacency->uptime)));
    }
}

void isis_update_interface_adjacency_from_hello(interface_t *iif, byte *hello_tlv_buffer, size_t tlv_buff_size)
{
    /* Algorithm: */
    /* 1. If isis_adjavency_t do not exists for an iif, create one during DOWN state */
    /* 2. Iterate over the hello_tlv_buffer and copy all 6 tlvs to the adjacency members */
    /* 3. Track if there is change in any attribute of existing adjacency in step 2 (bool nbr_attr_changed) */
    /* 4. Keep track if adjacency is newly created (bool new_adj) */

    bool new_adj = false;
    bool nbr_attr_changed = false;
    uint32_t ip_addr_int;
    bool force_bring_down_adj = false;
    bool regen_lsp = false;

    isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(iif);
    isis_adjacency_t *adjacency = isis_intf_info->adjacency;
    if(!adjacency){
        adjacency = calloc(1, sizeof(isis_adjacency_t));
        adjacency->intf = iif;
        new_adj = true;
        adjacency->adj_state = ISIS_ADJ_STATE_DOWN;
        isis_intf_info->adjacency = adjacency;
        isis_adjacency_start_delete_timer(adjacency);
    }

    byte tlv_type;
    byte tlv_len;
    byte *tlv_value = NULL;
    ITERATE_TLV_BEGIN(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buff_size){

        switch(tlv_type){

            case ISIS_TLV_HOSTNAME:
                if(memcmp(adjacency->nbr_name, tlv_value, tlv_len)){
                    memcpy(adjacency->nbr_name, tlv_value, tlv_len);
                    nbr_attr_changed = true;
                    regen_lsp = true;
                }
                break;
            case ISIS_TLV_RTR_ID:
                if(adjacency->nbr_rtr_id != *(uint32_t *)(tlv_value)){
                    adjacency->nbr_rtr_id = *(uint32_t *)(tlv_value);
                    nbr_attr_changed = true;
                }
                break;
            case ISIS_TLV_IF_IP:
                memcpy((byte *)&ip_addr_int, tlv_value, ip_addr_int);
                if(adjacency->nbr_intf_ip != ip_addr_int){
                    nbr_attr_changed = true;
                    adjacency->nbr_intf_ip = ip_addr_int;
                    force_bring_down_adj = true;
                    regen_lsp = true;
                }
                break;
            case ISIS_TLV_IF_INDEX:
                if(adjacency->remote_if_index != *(uint32_t *)(tlv_value)){
                    memcpy((byte *)&adjacency->remote_if_index, tlv_value, tlv_len);
                    regen_lsp = true;
                }
                break;
            case ISIS_TLV_HOLD_TIME:
                adjacency->hold_time = *(uint32_t *)(tlv_value);
                break;
            case ISIS_TLV_METRIC_VAL:
                if (adjacency->cost != *(uint32_t *)(tlv_value))
                {
                    adjacency->cost = *(uint32_t *)(tlv_value);
                    nbr_attr_changed = true;
                    regen_lsp = true;
                }
                break;
            case ISIS_TLV_IF_MAC:
                if (memcmp(adjacency->nbr_mac.mac_addr, (byte *)tlv_value, tlv_len))
                {
                    memcpy(adjacency->nbr_mac.mac_addr, tlv_value, tlv_len);
                    force_bring_down_adj = true;
                }
                break;
            #if ISIS_ENABLE_AUTH       
            case ISIS_TLV_IF_AUTH:
            {
                if(ISIS_INTF_IS_AUTH_ENABLED(iif)){
                    if(!memcmp(&adjacency->passcode, (byte *)tlv_value, tlv_len))
                        assert(0);
                }
                break;
            }
            #endif
            default:
                ;
        }
    }ITERATE_TLV_END(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlkv_buff_size);

    if(!new_adj){
        isis_adj_state_t next_state;
        if(force_bring_down_adj){
            next_state = ISIS_ADJ_STATE_DOWN;
        }
        else{
            next_state = isis_get_next_adj_state_on_receiving_next_hello(adjacency);
        }
        isis_change_adjacency_state(adjacency, next_state);
    }

    if(!new_adj && regen_lsp){
        isis_schedule_lsp_pkt_generation(adjacency->intf->att_node);
    }
    ISIS_INTF_INCREMENT_STATS(iif, good_hello_pkt_recvd);

    if((ISIS_NODE_INFO(iif->att_node)->layer2_mapping == true) && (adjacency->adj_state == ISIS_ADJ_STATE_UP)){
        isis_update_layer2_mapping_on_adjacency_up(adjacency);
    }
}

isis_adj_state_t isis_get_next_adj_state_on_receiving_next_hello(isis_adjacency_t *adjacency)
{
    switch(adjacency->adj_state){
        case ISIS_ADJ_STATE_DOWN:
            return ISIS_ADJ_STATE_INIT;
        case ISIS_ADJ_STATE_INIT:
            return ISIS_ADJ_STATE_UP;
        case ISIS_ADJ_STATE_UP:
            return ISIS_ADJ_STATE_UP;
        default:
            ;
    }
}

void isis_change_adjacency_state(isis_adjacency_t *adjacency, isis_adj_state_t new_adj_state)
{
    isis_adj_state_t old_adj_state = adjacency->adj_state;
    node_t *node = adjacency->intf->att_node;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    switch(old_adj_state){

        case ISIS_ADJ_STATE_DOWN:
        {
           switch(new_adj_state){

                case ISIS_ADJ_STATE_DOWN:
                {
                    break;
                }
                case ISIS_ADJ_STATE_INIT:
                {
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_delete_timer(adjacency);
                    isis_adjacency_start_expiry_timer(adjacency);
                    break;
                }
                case ISIS_ADJ_STATE_UP:
                {
                    break;
                }
                default:
                    ;
            } 
        }

        case ISIS_ADJ_STATE_INIT:
        {
            switch(new_adj_state){

                case ISIS_ADJ_STATE_DOWN:
                {
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_delete_timer(adjacency);
                    isis_adjacency_stop_expiry_timer(adjacency);
                    break;
                }
                case ISIS_ADJ_STATE_INIT:
                {
                    break;
                }
                case ISIS_ADJ_STATE_UP:
                {
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    isis_adjacency_set_uptime(adjacency);
                    node_info->adj_up_count++;
                    if(!isis_is_reconciliation_in_progress(adjacency->intf->att_node)){
                        isis_enter_reconciliation_phase(adjacency->intf->att_node);
                    }
                    else
                    {
                        isis_restart_reconciliation_timer(adjacency->intf->att_node);
                    }
                    isis_schedule_lsp_pkt_generation(adjacency->intf->att_node);
                    break;
                }
                default:
                    ;
            } 
        }

        case ISIS_ADJ_STATE_UP:
        {
            switch(new_adj_state){

                case ISIS_ADJ_STATE_DOWN:
                {
                    adjacency->adj_state = new_adj_state;
                    isis_adjacency_stop_expiry_timer(adjacency);
                    isis_adjacency_start_delete_timer(adjacency);
                    node_info->adj_up_count--;
                    isis_schedule_lsp_pkt_generation(adjacency->intf->att_node);
                    break;
                }
                case ISIS_ADJ_STATE_INIT:
                {
                    break;
                }
                case ISIS_ADJ_STATE_UP:
                {
                    isis_adjacency_refresh_expiry_timer(adjacency);
                    break;
                }
                default:
                    ;
            } 
        }

        default:
            ;
    }
}

void isis_adjacency_set_uptime(isis_adjacency_t *adjacency)
{
    assert(adjacency->adj_state == ISIS_ADJ_STATE_UP);
    adjacency->uptime = time(NULL);
}

void isis_delete_adjacency(isis_adjacency_t *adjacency)
{
    interface_t *intf = adjacency->intf;
    isis_intf_info_t *intf_info = ISIS_INTF_INFO(intf);
    assert(intf_info);
    intf_info->adjacency = NULL;

    isis_adjacency_stop_expiry_timer(adjacency);
    isis_adjacency_stop_delete_timer(adjacency);
    if(adjacency->adj_state == ISIS_ADJ_STATE_UP){
        node_t *node = intf->att_node;
        isis_node_info_t *node_info = ISIS_NODE_INFO(node);
        node_info->adj_up_count--;
    }
    free(adjacency);
}


