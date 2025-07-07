#ifndef __ISIS_PKT__
#define __ISIS_PKT__

typedef uint16_t isis_pkt_type_t;
typedef uint8_t  isis_pkt_hdr_flags_t;

#pragma pack (push, 1)
typedef struct isis_pkt_hdr_{
    isis_pkt_type_t isis_pkt_type;
    uint32_t seq_no;
    uint32_t rtr_id;
    isis_pkt_hdr_flags_t flags;
}isis_pkt_hdr_t;
#pragma pack(pop)

typedef struct isis_lsp_pkt_{
    /* pointer to lsp pkt buffer with the eth header */
    byte *pkt;
    /* size of lsp pkt including  ethenet encapsulation */
    size_t pkt_size;

    /* Ref_count */
    uint16_t ref_count;
}isis_lsp_pkt_t;

bool isis_pkt_trap_rule(char *pkt, size_t pkt_size);

void isis_pkt_receive(void *arg, size_t arg_size);

byte *isis_prepare_hello_pkt(interface_t *intf, size_t *hello_pkt_size);

void isis_print_pkt(void *arg, size_t arg_size);

void isis_create_fresh_lsp_pkt(node_t *node);

uint32_t *isis_get_lsp_pkt_rtr_id(isis_lsp_pkt_t *lsp_pkt);

uint32_t *isis_get_lsp_pkt_seq_no(isis_lsp_pkt_t *lsp_pkt);

void isis_ref_isis_pkt(isis_lsp_pkt_t *lsp_pkt);

void isis_deref_isis_pkt(isis_lsp_pkt_t *lsp_pkt);

#endif