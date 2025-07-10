#ifndef _ISIS_LSDB_H
#define _ISIS_LSDB_H

typedef struct node_ node_t;
typedef struct isis_lsp_pkt_ isis_lsp_pkt_t;
typedef struct isis_pkt_hdr_ isis_pkt_hdr_t;
typedef struct avltree avltree_t;

void isis_schedule_lsp_pkt_generation(node_t *node);

byte *isis_print_lsp_id(isis_lsp_pkt_t *lsp_pkt);

uint32_t isis_show_one_lsp_pkt_detail(byte *buff, isis_pkt_hdr_t *lsp_pkt_hdr, size_t pkt_size);

void isis_show_lspdb(node_t *node);

void isis_show_lspdb_detail(node_t *node);

void isis_cleanup_lspdb(node_t *node);

avltree_t *isis_get_lspdb_root(node_t *node);

void isis_remove_lsp_pkt_from_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt);

bool isis_add_lsp_pkt_to_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void isis_remove_lsp_entry_from_lspdb(node_t *node, uint32_t rtr_id);

isis_lsp_pkt_t *isis_lookup_lsp_entry_from_lspdb(node_t *node, uint32_t rtr_id);

void isis_free_dummy_lsp_pkt(void);

bool isis_our_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void isis_install_lsp(node_t *node, interface_t *iif, isis_lsp_pkt_t *new_lsp_pkt);

void isis_start_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt);

void isis_stop_lsp_pkt_installation_timer(isis_lsp_pkt_t *lsp_pkt);

void isis_refresh_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt);

#endif