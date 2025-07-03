#ifndef _ISIS_LSDB_H
#define _ISIS_LSDB_H

typedef struct node_ node_t;
typedef struct isis_lsp_pkt_ isis_lsp_pkt_t;
typedef struct isis_pkt_hdr_ isis_pkt_hdr_t;

void isis_schedule_lsp_pkt_generation(node_t *node);

byte *isis_print_lsp_id(isis_lsp_pkt_t *lsp_pkt);

uint32_t isis_show_one_lsp_pkt_detail(byte *buff, isis_pkt_hdr_t *lsp_pkt_hdr, size_t pkt_size);

#endif