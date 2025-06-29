#ifndef _ISIS_L2MAP_H
#define _ISIS_L2MAP_H

typedef struct node_ node_t;
typedef struct isis_adjacency_ isis_adjacency_t;

/* return true if layer2 mapping is enabled, else return false */
bool isis_is_layer2_mapping_enabled(node_t * node);

int isis_enable_layer2_mapping(node_t *node);

int isis_disable_layer2_mapping(node_t *node);

bool isis_update_layer2_mapping_on_adjacency_up(isis_adjacency_t *adjacency);

bool isis_update_layer2_mapping_on_adjacency_down(isis_adjacency_t *adjacency);

#endif