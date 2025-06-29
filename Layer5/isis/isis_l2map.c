#include "../../tcp_public.h"
#include "isis_l2map.h"
#include <stdbool.h>
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"

bool isis_is_layer2_mapping_enabled(node_t *node)
{
  return (node->node_nw_prop.isis_node_info->layer2_mapping);
}

int isis_enable_layer2_mapping(node_t *node)
{
    node->node_nw_prop.isis_node_info->layer2_mapping = true;
}

int isis_disable_layer2_mapping(node_t *node)
{
    uint8_t idx = 0U;
    isis_adjacency_t *adjacency;
    interface_t *intf;
    node->node_nw_prop.isis_node_info->layer2_mapping = false;
    for(; idx < MAX_IF_PER_NODE; idx++){
        intf = node->intf[idx];
        adjacency = ISIS_INTF_INFO(intf)->adjacency;
        isis_update_layer2_mapping_on_adjacency_down(adjacency);
    }
}

bool isis_update_layer2_mapping_on_adjacency_up(isis_adjacency_t *adjacency)
{
    arp_entry_t *arp_entry;
    node_t *node = adjacency->intf->att_node;
    if(!node)
        return false;
    arp_table_t *arp_table = NODE_ARP_TABLE(node);
    if (!arp_table)
        return false;
    arp_entry = arp_table_lookup(arp_table, adjacency->nbr_intf_ip);
    if(arp_entry)
        return false;
    arp_entry = (arp_entry_t *)calloc(1, sizeof(arp_entry_t));
    strncpy(arp_entry->ip_addr.ip_addr, adjacency->nbr_intf_ip, 16);
    arp_entry->ip_addr.ip_addr[15] = '\0';
    memcpy(arp_entry->mac_addr.mac_addr, adjacency->nbr_mac.mac_addr, sizeof(mac_add_t));
    strncpy(arp_entry->oif_name, adjacency->intf->if_name, IF_NAME_SIZE);
    arp_entry->oif_name[IF_NAME_SIZE - 1] = '\0';
    arp_entry->is_sane = false;
    arp_entry->proto = PROTO_ISIS;
    arp_table_entry_add(node, arp_table, arp_entry, 0);
    return true;
}

bool isis_update_layer2_mapping_on_adjacency_down(isis_adjacency_t *adjacency)
{
    node_t *node = adjacency->intf->att_node;
    if(!node)
        return false;
    arp_table_t *arp_table = NODE_ARP_TABLE(node);
    if(!arp_table)
        return false;
    delete_arp_table_entry(arp_table, adjacency->nbr_intf_ip);
    return true;
}