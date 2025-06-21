#ifndef __ISIS_INTF_H__
#define __ISIS_INTF_H__

typedef struct isis_intf_info_{

    /* Cost associated with the interface */
    uint32_t cost;
    /* Time interval in secs, at which hello pkt is sent */
    uint32_t hello_interval;
}isis_intf_info_t;

#define ISIS_INTF_INFO(intf_ptr) ((isis_intf_info_t *)((intf_ptr)->intf_nw_prop.isis_intf_info))
#define ISIS_INTF_COST(intf_ptr) (((isis_intf_info_t *)((intf_ptr)->intf_nw_prop.isis_intf_info))->cost)
#define ISIS_INTF_HELLO_INTERVAL(intf_ptr) (((isis_intf_info_t *)((intf_ptr)->intf_nw_prop.isis_intf_info))->hello_interval)

bool isis_is_protocol_enable_on_node_intf(interface_t *interface);
void isis_enable_protocol_on_interface(interface_t *intf);
void isis_disable_protocol_on_interface(interface_t *intf);

#endif