#include "../../tcp_public.h"
#include "isis_intf.h"

bool isis_is_protocol_enable_on_node_intf(interface_t *interface)
{
    if(ISIS_INTF_INFO(interface))
        return true;
    
    return false;
}