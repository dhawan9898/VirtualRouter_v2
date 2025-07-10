#ifndef __ISIS_EVENTS_H
#define __ISIS_EVENTS_H

typedef enum isis_event_type_ {

    isis_event_none,
    /*lspdb update events begin*/
    isis_event_self_duplicate_lsp,
    isis_event_self_fresh_lsp,
    isis_event_self_new_lsp,
    isis_event_self_old_lsp,
    isis_event_remote_duplicate_lsp,
    isis_event_remote_fresh_lsp,
    isis_event_remote_new_lsp,
    isis_event_remote_old_lsp,
    isis_event_max
} isis_event_type_t;

typedef enum isis_event_counter_ {
    isis_event_counter_none,
    /*lspdb update event counters */
    isis_event_counter_self_duplicate_lsp = 0U,
    isis_event_counter_self_fresh_lsp,
    isis_event_counter_self_new_lsp,
    isis_event_counter_self_old_lsp,
    isis_event_counter_remote_duplicate_lsp,
    isis_event_counter_remote_fresh_lsp,
    isis_event_counter_remote_new_lsp,
    isis_event_counter_remote_old_lsp,
    isis_event_counter_state_up_down,
    isis_event_counter_state_up_up,
    isis_event_counter_state_down_init,
    isis_event_counter_state_init_down,
    isis_event_counter_state_init_up,
    isis_event_counter_delete_lsp,
    isis_event_counter_generate_lsp,
    isis_event_counter_create_adjacency,
    isis_event_counter_delete_adjacency,
    isis_event_counter_max
} isis_event_counter_t;


const char *isis_event_str(isis_event_type_t isis_event_type);

void isis_increment_event_counter(isis_event_counter_t event_counter);

uint32_t isis_get_event_counter_value(isis_event_counter_t event_counter);

void isis_print_event_counters(void);

#endif