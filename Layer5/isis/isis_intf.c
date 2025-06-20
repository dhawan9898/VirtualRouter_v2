#include <unistd.h>
#include "../../tcp_public.h"
#include "isis_intf.h"
#include "isis_rtr.h"


bool isis_is_protocol_enable_on_node_intf(interface_t *interface)
{
    if(ISIS_INTF_INFO(interface))
        return true;
    
    return false;
}

void isis_enable_protocol_on_interface(interface_t *intf)
{
    isis_intf_info_t *isis_intf_info = NULL;

    /* Check if protocol is enabled on the attached node (other end of the link) */
    if(ISIS_NODE_INFO(intf->att_node)){
        printf("%s: Error - Protocol not enabled at the node level\n", __FUNCTION__);
        return;
    }

    /* Check if the protocol is enabled for the interface */
    if(ISIS_INTF_INFO(intf)){
        printf("%s: Error - Protocol not enabled for the interface\n", __FUNCTION__);
        return;       
    }

    isis_intf_info = calloc(1, sizeof(isis_intf_info_t));
    intf->intf_nw_prop.isis_intf_info = isis_intf_info;
}

void isis_disable_protocol_on_interface(interface_t *intf)
{
    isis_intf_info_t *isis_intf_info = NULL;
    isis_intf_info = intf->intf_nw_prop.isis_intf_info;
    free(isis_intf_info);
    intf->intf_nw_prop.isis_intf_info = NULL;
}