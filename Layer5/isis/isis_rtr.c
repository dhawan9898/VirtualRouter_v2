#include "../../tcp_public.h"
#include "isis_rtr.h"

bool isis_is_protocol_enable_on_node(node_t *node)
{
    if(ISIS_NODE_INFO(node))
        return true;
    
    return false;
}

void isis_show_node_protocol_state(node_t *node)
{
    printf("ISIS Protocol : %s\n", isis_is_protocol_enable_on_node(node) ? "Enable" : "Disable");
}

void isis_init(node_t *node)
{
    printf("%s\n",__FUNCTION__);
}

void isis_de_init(node_t *node)
{
    printf("%s\n",__FUNCTION__);
}