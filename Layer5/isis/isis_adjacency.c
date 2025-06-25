#include "../../tcp_public.h"
#include "isis_adjacency.h"
#include "isis_intf.h"
#include "isis_const.h"

static void isis_adjacency_start_delete_timer(isis_adjacency_t *adjacency)
{

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
                    nbr_attr_changed = true;
                    regen_lsp = true;
                    memcpy(adjacency->nbr_name, tlv_value, tlv_len);
                }
                break;
            case ISIS_TLV_RTR_ID:
                if(adjacency->nbr_rtr_id != *(uint32_t *)(tlv_value)){
                    nbr_attr_changed = true;
                    adjacency->nbr_rtr_id = *(uint32_t *)(tlv_value);
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

                break;
            case ISIS_TLV_IF_MAC:

                break;
            default:
                ;
        }

    }ITERATE_TLV_END(hello_tlv_buffer, tlv_type, tlv_len, tlv_value, tlkv_buff_size);
}