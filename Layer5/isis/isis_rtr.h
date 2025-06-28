#ifndef __ISIS_RTR_H__
#define __ISIS_RTR_H__

typedef struct isis_timer_data_ {

    node_t *node;
    interface_t *intf;
    void *data;
    size_t data_size;
} isis_timer_data_t;

typedef struct isis_node_info_{
    uint16_t adj_up_count;
}isis_node_info_t;

#define ISIS_NODE_INFO(node_ptr) (isis_node_info_t *)((node_ptr)->node_nw_prop.isis_node_info)
#define ISIS_INCREMENT_NODE_STATS(node_ptr, field)  ((ISIS_NODE_INFO(node_ptr))->field++)
#define ISIS_DECREMENT_NODE_STATS(node_ptr, field)  ((ISIS_NODE_INFO(node_ptr))->field--)

void isis_init(node_t *node);
void isis_de_init(node_t *node);

bool isis_is_protocol_enable_on_node(node_t *node);
void isis_show_node_protocol_state(node_t *node);
void isis_one_time_registration(void);

#endif