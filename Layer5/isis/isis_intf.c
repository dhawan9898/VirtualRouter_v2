#include <unistd.h>
#include <assert.h>
#include "../../tcp_public.h"
#include "../../WheelTimer/WheelTimer.h"
#include "isis_intf.h"
#include "isis_rtr.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "tcp_ip_trace.h"
#include "isis_adjacency.h"

extern char tlb[TCP_LOG_BUFFER_LEN];

bool isis_node_intf_is_enable(interface_t *intf) {

    return !(intf->intf_nw_prop.isis_intf_info == NULL);
}

bool isis_interface_qualify_to_send_hellos(interface_t *intf){

    if(isis_node_intf_is_enable(intf) && IS_INTF_L3_MODE(intf) && IF_IS_UP(intf)){
        return true;
    }
    return false;
}

bool isis_is_protocol_enable_on_node_intf(interface_t *interface)
{
    if(ISIS_INTF_INFO(interface))
        return true;
    
    return false;
}

void isis_show_interface_protocol_state(interface_t *intf) {

    bool is_enabled;
    glthread_t *curr;
    isis_adjacency_t *adjacency = NULL;
    isis_intf_info_t *isis_intf_info = NULL;

    is_enabled = isis_node_intf_is_enable(intf);

    printf(" %s : %sabled\n", intf->if_name, is_enabled ? "En" : "Dis");
    
    if(!is_enabled) return;

    isis_intf_info = ISIS_INTF_INFO(intf);
  
    PRINT_TABS(2);
    printf("hello interval : %u sec, Intf Cost : %u\n",
        isis_intf_info->hello_interval, isis_intf_info->cost);

    PRINT_TABS(2);
    printf("hello Transmission : %s\n",
        ISIS_INTF_HELLO_XMIT_TIMER(intf) ? "On" : "Off");  

    PRINT_TABS(2);
    printf("Adjacencies :\n");

   adjacency = isis_intf_info->adjacency;
   if (!adjacency) return;
   isis_show_adjacency(adjacency, 4);
   printf("\n");
}

void isis_enable_protocol_on_interface(interface_t *intf)
{
    isis_intf_info_t *isis_intf_info = NULL;
    node_t *node;
    node = intf->att_node;

    /* Check if protocol is enabled on the attached node (other end of the link) */
    if(!ISIS_NODE_INFO(node)){
        printf("%s: Error - Protocol not enabled at the node level\n", __FUNCTION__);
        return;
    }

    /* Check if the protocol is enabled for the interface */
    if(ISIS_INTF_INFO(intf)){
        printf("%s: Error - Protocol already enabled for the interface\n", __FUNCTION__);
        return;       
    }

    isis_intf_info = calloc(1, sizeof(isis_intf_info_t));
    intf->intf_nw_prop.isis_intf_info = isis_intf_info;
    isis_intf_info->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    isis_intf_info->cost = ISIS_DEFAULT_INTF_COST;

    sprintf(tlb, "%s: Protocol is enabled on interface\n", ISIS_CONFIG_TRACE);
    tcp_trace(intf->att_node, intf, tlb);

    if(isis_intf_info->hello_xmit_timer == NULL){
        if(isis_interface_qualify_to_send_hellos(intf)){
            printf("%s: Start sending hello pkts\n", __FUNCTION__);
            isis_start_sending_hellos(intf);
        }
    }
}

void isis_disable_protocol_on_interface(interface_t *intf)
{
    isis_intf_info_t *isis_intf_info = NULL;
    isis_intf_info = intf->intf_nw_prop.isis_intf_info;
    if(!isis_intf_info)
        return;

    isis_stop_sending_hellos(intf);
    isis_delete_adjacency(isis_intf_info->adjacency);
    free(isis_intf_info);
    intf->intf_nw_prop.isis_intf_info = NULL;
}

void isis_start_sending_hellos(interface_t *intf)
{
    node_t *node;
    size_t hello_pkt_size;
    assert(ISIS_INTF_HELLO_XMIT_TIMER(intf) == NULL);
    assert(isis_node_intf_is_enable(intf));

    node = intf->att_node;
    wheel_timer_t *wt = node_get_timer_instance(node);

    byte *hello_pkt = isis_prepare_hello_pkt(intf, &hello_pkt_size);
    isis_timer_data_t *isis_timer_data = calloc(1, sizeof(isis_timer_data_t));
    isis_timer_data->node = intf->att_node;
    isis_timer_data->intf = intf;
    isis_timer_data->data = (void *)hello_pkt;
    isis_timer_data->data_size = hello_pkt_size;

    ISIS_INTF_HELLO_XMIT_TIMER(intf)  = register_app_event(wt, 
                                              isis_transmit_hello,
                                              (void *)isis_timer_data,
                                              sizeof(isis_timer_data_t), 3,
                                              //ISIS_INTF_HELLO_INTERVAL(intf) * 1000,
                                              1);
    //printf("%s\n",__FUNCTION__);
}

void isis_stop_sending_hellos(interface_t *intf) {

    timer_event_handle *hello_xmit_timer = NULL;

    hello_xmit_timer =  ISIS_INTF_HELLO_XMIT_TIMER(intf);

    if (!hello_xmit_timer) return;

    isis_timer_data_t *isis_timer_data =(isis_timer_data_t *)wt_elem_get_and_set_app_data(hello_xmit_timer, 0); //just cleaning up heelo_xmit_timer

    tcp_ip_free_pkt_buffer(isis_timer_data->data, isis_timer_data->data_size);

    free(isis_timer_data);

    de_register_app_event(hello_xmit_timer);
    ISIS_INTF_HELLO_XMIT_TIMER(intf) = NULL;
}

void isis_interface_updates(void *arg, size_t arg_size)
{

}