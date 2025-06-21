#ifndef __ISIS_INTF_H__
#define __ISIS_INTF_H__

#include "isis_rtr.h"

typedef struct isis_intf_info_{

    /* Cost associated with the interface */
    uint32_t cost;
    /* Time interval in secs, at which hello pkt is sent */
    uint32_t hello_interval;
    /* timer for sending hello pkts periodically */
    timer_event_handle *hello_xmit_timer;
    uint32_t hello_pkt_sent;

}isis_intf_info_t;

#define ISIS_INTF_INFO(intf_ptr) ((isis_intf_info_t *)((intf_ptr)->intf_nw_prop.isis_intf_info))
#define ISIS_INTF_COST(intf_ptr) (((isis_intf_info_t *)((intf_ptr)->intf_nw_prop.isis_intf_info))->cost)
#define ISIS_INTF_HELLO_INTERVAL(intf_ptr) (((isis_intf_info_t *)((intf_ptr)->intf_nw_prop.isis_intf_info))->hello_interval)
#define ISIS_INTF_HELLO_XMIT_TIMER(intf_ptr)  \
    (((isis_intf_info_t *)((intf_ptr)->intf_nw_prop.isis_intf_info))->hello_xmit_timer)
#define ISIS_INTF_INCREMENT_STATS(intf_ptr, pkt_type)  (((ISIS_INTF_INFO(intf_ptr))->pkt_type)++)

bool isis_node_intf_is_enable(interface_t *intf);
bool isis_is_protocol_enable_on_node_intf(interface_t *interface);
void isis_enable_protocol_on_interface(interface_t *intf);
void isis_disable_protocol_on_interface(interface_t *intf);
void isis_start_sending_hellos(interface_t *intf);
void isis_stop_sending_hellos(interface_t *intf);


static void isis_transmit_hello(void *arg, uint32_t arg_size) {

    if (!arg) return;

    isis_timer_data_t *isis_timer_data = (isis_timer_data_t *)arg;

    node_t *node = isis_timer_data->node;
    interface_t *intf = isis_timer_data->intf;
    byte *hello_pkt = (byte *)isis_timer_data->data;
    uint32_t pkt_size = isis_timer_data->data_size;

    send_pkt_out(hello_pkt, pkt_size, intf);
    ISIS_INTF_INCREMENT_STATS(intf, hello_pkt_sent);
}

#endif