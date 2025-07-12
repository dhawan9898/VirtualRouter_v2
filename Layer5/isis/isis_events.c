#include "../../tcp_public.h"
#include "isis_events.h"

static uint32_t isis_event_counters[isis_event_counter_max];

static char isis_event_str_arr[isis_event_max][128] =
{
    /* Warning : Order must match with enums */
    "",                                 /* isis_event_none */
    /*lspdb update events*/
    "ISIS EVENT SELF DUPLICATE LSP",    /* isis_event_self_duplicate_lsp, */
    "ISIS EVENT SELF FRESH LSP",        /* isis_event_self_fresh_lsp, */
    "ISIS EVENT SELF NEW LSP",          /* isis_event_self_new_lsp, */
    "ISIS EVENT SELF OLD LSP",          /* isis_event_self_old_lsp, */
    "ISIS_EVENT_REMOTE_DUPLICATE_LSP",  /* isis_event_remote_duplicate_lsp */
    "ISIS_EVENT_REMOTE_FRESH_LSP",      /* isis_event_remote_fresh_lsp */
    "ISIS_EVENT_REMOTE_NEW_LSP",        /* isis_event_remote_new_lsp */
    "ISIS_EVENT_REMOTE_OLD_LSP"         /* isis_event_remote_old_lsp */
    "ISIS EVENT STATE UP DOWN",         /* isis_event_counter_state_up_down */
    "ISIS EVENT STATE UP UP",           /* isis_event_counter_state_up_up */
    "ISIS EVENT STATE DOWN INIT",       /* isis_event_counter_state_down_init */
    "ISIS EVENT STATE INIT DOWN",       /* isis_event_counter_state_init_down */
    "ISIS EVENT STATE INIT UP",         /* isis_event_counter_state_init_up */
    "ISIS EVENT DELETE LSP",            /* isis_event_counter_delete_lsp */
    "ISIS EVENT GENERATE LSP",          /* isis_event_counter_generate_lsp */
    "ISIS EVENT CREATE ADJACENCY",      /* isis_event_counter_create_adjacency */
    "ISIS EVENT DELETE ADJACENCY"       /* isis_event_counter_delete_adjacency */
    "ISIS EVENT RECONCILIATION TRIGGERED",      /* isis_event_counter_reconciliation_triggered */
    "ISIS_EVENT RECONCILIATION RESTARTED",      /* isis_event_counter_reconciliation_restarted */
    "ISIS EVENT RECONCILIATION EXIT",           /* isis_event_counter_reconciliation_exit */
    "ISIS EVENT ON DEMAND FLOOD"                /* isis_event_counter_on_demand_flood */
} ;

const char *isis_event_str(isis_event_type_t isis_event_type)
{
    return isis_event_str_arr[isis_event_type];
}

void isis_increment_event_counter(isis_event_counter_t event_counter)
{
    isis_event_counters[event_counter]++;
}

uint32_t isis_get_event_counter_value(isis_event_counter_t event_counter)
{
    return isis_event_counters[event_counter];
}

void isis_print_event_counters(void)
{
    isis_event_counter_t idx;
    for(idx = 1; idx < isis_event_counter_max; idx++){
        printf("\t%s : %u\n", isis_event_str(idx), isis_get_event_counter_value(idx));
    }
}

