#ifndef __ISIS_INTF_H__
#define __ISIS_INTF_H__


typedef struct isis_intf_info_{

}isis_intf_info_t;

#define ISIS_INTF_INFO(intf_ptr) (isis_intf_info_t *)(intf_ptr->intf_nw_prop.isis_intf_info)

bool isis_is_protocol_enable_on_node_intf(interface_t *interface);
void isis_enable_protocol_on_interface(interface_t *intf);
void isis_disable_protocol_on_interface(interface_t *intf);

#endif