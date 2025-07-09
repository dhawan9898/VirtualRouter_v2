#ifndef __ISIS_EVENTS_H
#define __ISIS_EVENTS_H

typedef enum isis_event_type_ {

    isis_event_none,
    /*lspdb update events begin*/
    isis_event_self_duplicate_lsp,
    isis_event_self_fresh_lsp,
    isis_event_self_new_lsp,
    isis_event_self_old_lsp,
    isis_event_max
} isis_event_type_t;

#endif