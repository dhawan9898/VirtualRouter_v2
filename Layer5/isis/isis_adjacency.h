#ifndef _ISIS_ADJACENCY_H
#define _ISIS_ADJACENCY_H

#include <stdint.h>
#include "net.h"

typedef enum isis_adj_state_ {

    ISIS_ADJ_STATE_UNKNOWN,
    ISIS_ADJ_STATE_DOWN,
    ISIS_ADJ_STATE_INIT,
    ISIS_ADJ_STATE_UP
} isis_adj_state_t;

typedef struct isis_adjacency_{

    /* backptr to the interface */
    interface_t *intf;
    /* Router id [or] Router's Loopback address */
    uint32_t nbr_rtr_id;
    /* hostame [or] device name */
    unsigned char nbr_name[NODE_NAME_SIZE];
	/* Nbr intf Ip */
    uint32_t nbr_intf_ip;   
    /* Mac Address */
    mac_add_t nbr_mac;
    /* Nbr if index */
    uint32_t remote_if_index;  
    /* Hold time in sec reported by nbr*/
    uint32_t hold_time;    
	/* Nbr link cost Value */
	uint32_t cost; 	
	/* Adj State */
    isis_adj_state_t adj_state;   
    /* uptime */
    time_t uptime;	
	 /* Expiry timer */
    timer_event_handle *expiry_timer;    
	/* Delete timer */
    timer_event_handle *delete_timer;

}isis_adjacency_t;

static inline char *isis_adj_state_str(isis_adj_state_t adj_state) {

    switch(adj_state){
        case ISIS_ADJ_STATE_DOWN:
            return "Down";
        case ISIS_ADJ_STATE_INIT:
            return "Init";
        case ISIS_ADJ_STATE_UP:
            return "Up";
        default : ;
    }
    return NULL;
}

#endif