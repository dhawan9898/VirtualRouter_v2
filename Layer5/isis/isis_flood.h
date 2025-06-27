#ifndef ISIS_FLOOD_H
#define ISIS_FLOOD_H

#include "../../tcp_public.h"

typedef struct node_ node_t;

/* Reconciliation API */
void isis_enter_reconciliation_phase(node_t *node);

void isis_exit_reconciliation_phase(node_t *node);

void isis_restart_reconciliation_timer(node_t *node);

void isis_start_reconciliation_timer(node_t *node);

void isis_stop_reconciliation_timer(node_t *node);

bool isis_is_reconciliation_in_progress(node_t *node);

#endif