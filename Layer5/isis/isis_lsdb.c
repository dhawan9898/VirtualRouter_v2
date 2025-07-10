#include "../../tcp_public.h"
#include "isis_lsdb.h"
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_rtr.h"
#include "isis_flood.h"
#include "isis_events.h"
#include "../../avlTree/avlTree.h"

static isis_lsp_pkt_t *gl_dummy_lsp_pkt = NULL;

static void isis_show_one_lsp_pkt( isis_lsp_pkt_t *lsp_pkt) {

    int rc = 0;
    ethernet_frame_t *eth_hdr = (ethernet_frame_t *)lsp_pkt->pkt;
    byte *lsp_hdr = eth_hdr->payload;

    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t *seq_no = isis_get_lsp_pkt_seq_no(lsp_pkt);

    byte *lsp_tlv_buffer = lsp_hdr + sizeof (isis_pkt_hdr_t);

    unsigned char *rtr_id_str = tcp_ip_convert_ip_n_to_p(*rtr_id, 0);
    printf("LSP : %-16s   Seq # : %-4u    size(B) : %-4lu    "
            "ref_c : %-3u   ",
            rtr_id_str, *seq_no, 
            lsp_pkt->pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD,
            lsp_pkt->ref_count);

    if (lsp_pkt->expiry_timer) {
        printf("Life Time Remaining : %u sec\n",
                      wt_get_remaining_time(lsp_pkt->expiry_timer) / 1000);
    }
    else {
        printf ("\n");
    }
}

static isis_lsp_pkt_t *isis_get_dummy_lsp_pkt_with_key(uint32_t rtr_id)
{
    if(!gl_dummy_lsp_pkt){
        gl_dummy_lsp_pkt = calloc(1, sizeof(isis_lsp_pkt_t));
        gl_dummy_lsp_pkt->pkt = tcp_ip_get_new_pkt_buffer(ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(isis_lsp_pkt_t));
        gl_dummy_lsp_pkt->pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(isis_lsp_pkt_t);
        gl_dummy_lsp_pkt->installed_in_db = false;
        isis_ref_isis_pkt(gl_dummy_lsp_pkt);
    }

    uint32_t *rtr_id_addr = isis_get_lsp_pkt_rtr_id(gl_dummy_lsp_pkt);
    *rtr_id_addr = rtr_id;
    return gl_dummy_lsp_pkt;
}

void isis_free_dummy_lsp_pkt(void)
{
    if(gl_dummy_lsp_pkt){
        isis_deref_isis_pkt(gl_dummy_lsp_pkt);
        gl_dummy_lsp_pkt = NULL;
    }
}

bool isis_our_lsp(node_t *node, isis_lsp_pkt_t *lsp_pkt) {

    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t node_lo_addr = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDRESS(node));

    return *rtr_id == node_lo_addr;
}

static void isis_generate_lsp_pkt(void *arg, uint32_t arg_size)
{
    node_t *node = (node_t *)arg;
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    sprintf(tlb, "%s : Self-LSP Generation task %p triggered\n", ISIS_LSPDB_TRACE,  node_info->lsp_pkt_gen_task);
    tcp_trace(node, NULL, tlb);
    node_info->lsp_pkt_gen_task = NULL;
    isis_create_fresh_lsp_pkt(node);
    isis_install_lsp(node, NULL, node_info->self_lsp_pkt);
}

void isis_schedule_lsp_pkt_generation(node_t *node)
{
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if(!node_info)
        return;
    if(node_info->lsp_pkt_gen_task){
        sprintf(tlb, "LSP generation already scheduled\n");
        tcp_trace(node, NULL, tlb);
        return;
    }
    node_info->lsp_pkt_gen_task = task_create_new_job(node, isis_generate_lsp_pkt, TASK_ONE_SHOT);
    sprintf(tlb, "LSP generation task scheduled\n");
    tcp_trace(node, NULL, tlb);
    //isis_create_fresh_lsp_pkt(node); // For Test; to be removed
    isis_increment_event_counter(isis_event_counter_generate_lsp);
}

byte *isis_print_lsp_id(isis_lsp_pkt_t *lsp_pkt)
{
    byte lsp_id[32];
    memset(lsp_id, 0, sizeof(lsp_id));
    uint32_t *rtr_id = isis_get_lsp_pkt_rtr_id(lsp_pkt);
    uint32_t *seq_no = isis_get_lsp_pkt_seq_no(lsp_pkt);

    sprintf(lsp_id, "%s-%s", tcp_ip_convert_ip_n_to_p((*rtr_id, NULL), *seq_no));
    return lsp_id;
}

/* Printing LSP packets */

static uint32_t isis_print_formatted_nbr_tlv22 (byte *buff, byte *nbr_tlv_buffer, uint8_t tlv_buffer_len) 
{
    uint32_t rc = 0;
    byte *subtlv_ptr;
    uint32_t ip_addr_int;
    uint32_t metric;
    uint8_t subtlv_len;

    byte tlv_type;
    byte tlv_len; 
    byte *tlv_value = NULL;

    ITERATE_TLV_BEGIN(nbr_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buffer_len) {

        /* Now we shall extract IP Addr, metric and subtlv len */
        ip_addr_int = *(uint32_t *)tlv_value;
        metric = *(uint32_t *)(((uint32_t *)tlv_value) + 1);
        subtlv_len = *(uint8_t *)((uint32_t *)tlv_value + 2);
        if (buff) {
            rc += sprintf(buff + rc, "\tTLV%d  Len : %d\n", tlv_type, tlv_len);
            rc += sprintf(buff + rc, "\t\tNbr Rtr ID : %s     metric : %u    SubTLV len : %d\n", \
                                                                    tcp_ip_convert_ip_n_to_p(ip_addr_int, 0), metric, subtlv_len);
        }
        else {
            rc += printf( "\tTLV%d  Len : %d\n", tlv_type, tlv_len);
            rc += printf("\t\tNbr Rtr ID : %s     metric : %u    SubTLV len : %d\n", \
                                                                    tcp_ip_convert_ip_n_to_p(ip_addr_int, 0), metric, subtlv_len);
        }
        subtlv_ptr = tlv_value + 
                            sizeof(uint32_t) +     // 4B of IP Addr ( nbr lo addr )
                            sizeof(uint32_t) +     // 4B of metric  
                            sizeof(uint8_t);       // 1B of subtlv len

        /* Now Read the Sub TLVs */
        byte tlv_type2, tlv_len2, *tlv_value2 = NULL;

        ITERATE_TLV_BEGIN (subtlv_ptr, tlv_type2, tlv_len2, tlv_value2, subtlv_len) {

            switch (tlv_type2) {
                case ISIS_TLV_IF_INDEX:
                {
                    if (buff) {
                        rc += sprintf (buff + rc, "\tSubTLV%d  Len : %d   if-indexes [local : %u, remote : %u]\n",
                                tlv_type2, tlv_len2, *(uint32_t *)tlv_value2, *(uint32_t *)((uint32_t *)tlv_value2 + 1));
                    }
                    else {
                        rc += printf ( "\tSubTLV%d  Len : %d   if-indexes [local : %u, remote : %u]\n",
                                tlv_type2, tlv_len2, *(uint32_t *)tlv_value2, *(uint32_t *)((uint32_t *)tlv_value2 + 1));
                    }
                    break;
                }
                case ISIS_TLV_LOCAL_IP:
                {
                    ip_addr_int = *(uint32_t *)tlv_value2;
                    if (buff) {
                        rc += sprintf (buff + rc , "\tSubTLV%d  Len : %d  Local IP : %s\n", tlv_type2, tlv_len2, \
                                                                    tcp_ip_convert_ip_n_to_p(ip_addr_int, 0));
                    }
                    else {
                        rc += printf ("\tSubTLV%d  Len : %d  Local IP : %s\n", tlv_type2, tlv_len2, tcp_ip_convert_ip_n_to_p(ip_addr_int, 0));
                    }
                    break;
                }
                case ISIS_TLV_REMOTE_IP:
                {
                    ip_addr_int = *(uint32_t *)tlv_value2;
                    if (buff) {
                        rc += sprintf (buff + rc , "\tSubTLV%d  Len : %d  Remote IP : %s\n", tlv_type2, tlv_len2, 
                                                                            tcp_ip_convert_ip_n_to_p(ip_addr_int, 0));
                    }
                    else {
                        rc += printf ("\tSubTLV%d  Len : %d  Remote IP : %s\n", tlv_type2, tlv_len2, 
                                                                    tcp_ip_convert_ip_n_to_p(ip_addr_int, 0));
                    }
                    break;
                }
                default: 
                    ;
            }
        } ITERATE_TLV_END (subtlv_ptr, tlv_type2, tlv_len2, tlv_value2, subtlv_len);
    }ITERATE_TLV_END(nbr_tlv_buffer, tlv_type, tlv_len, tlv_value, tlv_buffer_len);
    return rc;
}

uint32_t isis_show_one_lsp_pkt_detail(byte *buff, isis_pkt_hdr_t *lsp_pkt_hdr, size_t pkt_size)
{
   uint32_t rc = 0;
   isis_lsp_pkt_t *lsp_pkt;
   
   byte tlv_type;
   byte tlv_len;
   byte *tlv_value = NULL;
   
   if(buff){
        rc += sprintf(buff + rc, "LSP ID : %s(%u)\n", tcp_ip_convert_ip_n_to_p(lsp_pkt_hdr->rtr_id, NULL), lsp_pkt_hdr->seq_no);
        rc += sprintf(buff + rc, "Flags : 0x%x\n", lsp_pkt_hdr->flags);
        rc += sprintf(buff + rc, "TLVs\n");
   }
   else{
        rc += printf("LSP ID : %s(%u)\n", tcp_ip_convert_ip_n_to_p(lsp_pkt_hdr->rtr_id, NULL), lsp_pkt_hdr->seq_no);
        rc += printf("Flags : 0x%x\n", lsp_pkt_hdr->flags);
        rc += printf("TLVs\n");
   }
   byte *lsp_tlv_buffer = (byte *)(lsp_pkt_hdr + 1U);
   uint16_t lsp_tlv_buffer_size = (uint16_t)(pkt_size -  sizeof(isis_pkt_hdr_t));

   ITERATE_TLV_BEGIN(lsp_tlv_buffer, tlv_type, tlv_len, tlv_value, lsp_tlv_buffer_size){

        switch(tlv_type)
        {
            case ISIS_TLV_HOSTNAME:
            {
                if(buff){
                    rc += sprintf(buff + rc, "\tTLV%d Host-Name : %s\n", tlv_type, tlv_value);
                }
                else{
                    rc += printf("\tTLV%d Host-Name : %s\n", tlv_type, tlv_value);
                }
                break;
            }
            case ISIS_IS_REACH_TLV:
            {
                rc += isis_print_formatted_nbr_tlv22(buff ? buff + rc  : NULL, tlv_value - TLV_OVERHEAD_SIZE, tlv_len + TLV_OVERHEAD_SIZE);
                break;
            }
        }

   }ITERATE_TLV_END(lsp_tlv_buffer, tlv_type, tlv_len, tlv_value, lsp_tlv_buffer_size);

   return rc;
}

void isis_show_lspdb(node_t *node)
{
    avltree_node_t *curr;
    isis_lsp_pkt_t *lsp_pkt;

    avltree_t *lspdb = isis_get_lspdb_root(node);
    if(!lspdb)
        return;
    ITERATE_AVL_TREE_BEGIN(lspdb, curr){

        lsp_pkt = avltree_container_of(curr, isis_lsp_pkt_t, avl_node_glue);
        isis_show_one_lsp_pkt(lsp_pkt);
    }ITERATE_AVL_TREE_END(lspdb, curr);
}

void isis_show_lspdb_detail(node_t *node) {

    avltree_node_t *curr;
    isis_lsp_pkt_t *lsp_pkt;
    
    avltree_t *lspdb = isis_get_lspdb_root(node);

    if (!lspdb) 
        return;

    ITERATE_AVL_TREE_BEGIN(lspdb, curr) {

        lsp_pkt = avltree_container_of(curr, isis_lsp_pkt_t, avl_node_glue);
        ethernet_frame_t *lsp_eth_hdr = (ethernet_frame_t *) (lsp_pkt->pkt);
        size_t pkt_size = lsp_pkt->pkt_size;
        isis_pkt_hdr_t *lsp_pkt_hdr = (isis_pkt_hdr_t *)(lsp_eth_hdr->payload);
        size_t lsp_pkt_size = pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(lsp_eth_hdr);
        if (!lsp_pkt) 
            continue;
        isis_show_one_lsp_pkt_detail (NULL, lsp_pkt_hdr, lsp_pkt_size);

    } ITERATE_AVL_TREE_END;
}

avltree_t *isis_get_lspdb_root(node_t *node)
{
    isis_node_info_t *node_info = ISIS_NODE_INFO(node);
    if(!node_info)
        return NULL;
    return &node_info->lspdb_avl_root;
}

void isis_remove_lsp_pkt_from_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt)
{
    avltree_t *lspdb = isis_get_lspdb_root(node);
    if(!lspdb)
        return;
    if(lsp_pkt->installed_in_db == false)
        return;
    avltree_remove(&lsp_pkt->avl_node_glue, lspdb);
    lsp_pkt->installed_in_db = false;
}

void isis_remove_lsp_entry_from_lspdb(node_t *node, uint32_t rtr_id)
{
    avltree_t *lspdb = isis_get_lspdb_root(node);
    if(!lspdb)
        return;
    isis_lsp_pkt_t *lsp_pkt = isis_lookup_lsp_entry_from_lspdb(node, rtr_id);
    if(!lsp_pkt)
        return;
    isis_remove_lsp_pkt_from_lspdb(node, lsp_pkt);
    isis_deref_isis_pkt(lsp_pkt);
}

bool isis_add_lsp_pkt_to_lspdb(node_t *node, isis_lsp_pkt_t *lsp_pkt)
{
    avltree_t *lspdb = isis_get_lspdb_root(node);
    if(!lspdb)
        return false;
    if(lsp_pkt->installed_in_db)
        return false;
    avltree_insert(&lsp_pkt->avl_node_glue, lspdb);
    lsp_pkt->installed_in_db = true;
    isis_ref_isis_pkt(lsp_pkt);
    return true;
}

isis_lsp_pkt_t *isis_lookup_lsp_entry_from_lspdb(node_t *node, uint32_t rtr_id)
{
    avltree_t *lspdb = isis_get_lspdb_root(node);
    if(!lspdb)
        return NULL;
    isis_lsp_pkt_t *dummy_lsp_pkt = isis_get_dummy_lsp_pkt_with_key(rtr_id);

    avltree_node_t *avl_node = avltree_lookup(&dummy_lsp_pkt->avl_node_glue, lspdb);
    if(!avl_node)
        return NULL;
    return avltree_container_of(avl_node, isis_lsp_pkt_t, avl_node_glue);
}

void isis_cleanup_lspdb(node_t *node)
{
    avltree_node_t *curr;
    isis_lsp_pkt_t *lsp_pkt;
    avltree_t *lspdb = isis_get_lspdb_root(node);
    if(!lspdb)
        return;
    
    ITERATE_AVL_TREE_BEGIN(lspdb, curr){

        lsp_pkt = avltree_container_of(curr, isis_lsp_pkt_t, avl_node_glue);
        isis_remove_lsp_pkt_from_lspdb(node, lsp_pkt);
    }ITERATE_AVL_TREE_END;
}

void isis_install_lsp(node_t *node, interface_t *iif, isis_lsp_pkt_t *new_lsp_pkt)
{
    bool self_lsp;
    bool recvd_via_intf;
    uint32_t *rtr_id;
    ip_add_t rtr_id_str;
    isis_lsp_pkt_t *old_lsp_pkt;
    isis_event_type_t event_type;
    bool duplicate_lsp;
    uint32_t *old_seq_no = NULL;
    uint32_t *new_seq_no = NULL;
    isis_node_info_t *node_info;

    self_lsp = isis_our_lsp(node, new_lsp_pkt);
    recvd_via_intf = iif ? true : false;
    event_type = isis_event_none;

    rtr_id = isis_get_lsp_pkt_rtr_id(new_lsp_pkt);
    tcp_ip_convert_ip_n_to_p(*rtr_id, rtr_id_str.ip_addr); /* Converting to print local ip/ router id in presentation form */

    old_lsp_pkt = isis_lookup_lsp_entry_from_lspdb(node, *rtr_id);
    if(old_lsp_pkt){
        old_seq_no = isis_get_lsp_pkt_seq_no(old_lsp_pkt);
    }
    new_seq_no = isis_get_lsp_pkt_seq_no(new_lsp_pkt);

    sprintf(tlb, "%s : Lsp Recvd : %s-%u(%p) on intf %s, old lsp : %s-%u(%p)\n",
        ISIS_LSPDB_TRACE,
        rtr_id_str.ip_addr, *new_seq_no, 
        new_lsp_pkt->pkt,
        iif ? iif->if_name : 0,
        old_lsp_pkt ? rtr_id_str.ip_addr : 0,
        old_lsp_pkt ? *old_seq_no : 0,
        old_lsp_pkt ? old_lsp_pkt->pkt : 0);
    tcp_trace(node, iif, tlb);

    duplicate_lsp = (old_lsp_pkt && (*old_seq_no == *new_seq_no));

    /* Self LSPs handling */
    /* Case #1 */
    if(self_lsp && duplicate_lsp)
    {
        event_type = isis_event_self_duplicate_lsp;
        sprintf(tlb, "\t%s : Event : %s : self Duplicate LSP, No Action\n",
            ISIS_LSPDB_TRACE, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        if(recvd_via_intf){
            /* No action - self lsp with same seq no may come through interface because of flooding */
        }
        else{
            /* self lsp with same seq no is not possible - seq no is supposed to increment in successive generations */
            assert(0);
        }
        isis_increment_event_counter(isis_event_counter_self_duplicate_lsp);
    }
    /* Case #2 */
    else if (self_lsp && !old_lsp_pkt)
    {
        event_type = isis_event_self_fresh_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_TRACE, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        if(recvd_via_intf){
            /* We will have to re-generate the self lsp, so that after forwarding all nodes has this lsp with the latest seq no */
            node_info = ISIS_NODE_INFO(node);
            node_info->seq_no = *new_seq_no;
            sprintf(tlb, "\t%s : Event : %s : self-LSP to be generated with seq no %u\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type), *new_seq_no + 1);
            tcp_trace(node, iif, tlb);

            isis_schedule_lsp_pkt_generation(node);
        }else{
            /* add the newly generated lsp pkt to database and schedule lsp flooding */
            sprintf(tlb, "\t%s : Event : %s : LSP to be Added in LSPDB and flood\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type));
            tcp_trace(node, iif, tlb);

            isis_add_lsp_pkt_to_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, 0);
        }
        isis_increment_event_counter(isis_event_counter_self_fresh_lsp);
    }
    /* Case #3 */
    else if (self_lsp && old_lsp_pkt && (*new_seq_no > *old_seq_no))
    {
        event_type = isis_event_self_new_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_TRACE, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        if(recvd_via_intf){
            /* lsp pkt has to be re-generated - either someone is sending manipulated lsp pkts or local database update failed*/
            node_info = ISIS_NODE_INFO(node);
            node_info->seq_no = *new_seq_no;
             sprintf(tlb, "\t%s : Event : %s : self-LSP to be generated with seq no %u\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type), *new_seq_no + 1);
            tcp_trace(node, iif, tlb);
            isis_schedule_lsp_pkt_generation(node);
        }else{
            /* update the database with the latest self lsp pkt */
            sprintf(tlb, "\t%s : Event : %s : LSP %s-%u to be replaced in LSPDB "
                "with new LSP %s-%u and flood\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type),
                rtr_id_str.ip_addr, *old_seq_no,
                rtr_id_str.ip_addr, *new_seq_no);
            isis_remove_lsp_pkt_from_lspdb(node, old_lsp_pkt);
            isis_add_lsp_pkt_to_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, 0);
        }
        isis_increment_event_counter(isis_event_counter_self_new_lsp);
    }
    /* Case #4 */
    else if (self_lsp && old_lsp_pkt && (*new_seq_no < *old_seq_no))
    {
        event_type = isis_event_self_old_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_TRACE, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        if(recvd_via_intf){
            /* No action - looks like an old pkt is still circulating. We ignore so as to avoid further forwarding it */
            sprintf(tlb, "\t%s : Event : %s Recvd Duplicate LSP %s-%u, no Action\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type),
                rtr_id_str.ip_addr, *new_seq_no);
            tcp_trace(node, iif, tlb);
        }else{
            /* This should'nt be valid */
            assert(0);
        }
        isis_increment_event_counter(isis_event_counter_self_old_lsp);
    }

    /* Remote LSPs handling */
    /* Case #1 remote lsp with same sequence number as exiting in lsp database */
    else if(!self_lsp && duplicate_lsp)
    {
        event_type = isis_event_remote_duplicate_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_TRACE, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        if(recvd_via_intf)
        {
            /* Ignore the pkt; No need to forward also */
            sprintf(tlb, "\t%s : Event : %s Recvd Duplicate LSP %s-%u, no Action\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type), rtr_id_str.ip_addr, *new_seq_no);
            tcp_trace(node, iif, tlb);
        }
        else{
            /* There is no way a lsp belonging to other node, reaching us without being received by an interface */
            assert(0);
        }
        isis_increment_event_counter(isis_event_counter_remote_duplicate_lsp);
    }

    /* Case #2  remote lsp which is fresh (no prev. entries in lsp database)*/
    else if(!self_lsp && !old_lsp_pkt)
    {
        event_type = isis_event_remote_fresh_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_TRACE, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        if(recvd_via_intf)
        {
            /* New lsps should be added to database and also should be forwarded */
            sprintf(tlb, "\t%s : Event : %s : LSP %s-%u to be Added in LSPDB and flood\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type), rtr_id_str.ip_addr, *new_seq_no);
            tcp_trace(node, iif, tlb);
            isis_add_lsp_pkt_to_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, iif);
        }
        else{
            /* There is no way a lsp belonging to other node, reaching us without being received by an interface */
            assert(0);
        }
        isis_increment_event_counter(isis_event_counter_remote_fresh_lsp);
    }

    /* Case #3  remote lsp which has a new seq number than as the one in the lsp database */
    else if(!self_lsp && old_lsp_pkt && (*new_seq_no < *old_seq_no))
    {
        event_type = isis_event_remote_new_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_TRACE, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        if(recvd_via_intf)
        {
            /* Remove the lsp with lesser sequence number from lsp db
             * Add the lsp with greater seq no to the lspdb
             * forward flood the pkt   
            */
            sprintf(tlb, "\t%s : Event : %s : LSP %s-%u to be replaced in LSPDB with"
                " LSP %s-%u and flood\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type),
                rtr_id_str.ip_addr, *old_seq_no,
                rtr_id_str.ip_addr, *new_seq_no);
            tcp_trace(node, iif, tlb);
            isis_remove_lsp_pkt_from_lspdb(node, old_lsp_pkt);
            isis_add_lsp_pkt_to_lspdb(node, new_lsp_pkt);
            isis_schedule_lsp_flood(node, new_lsp_pkt, iif);
        }
        else{
            /* There is no way a lsp belonging to other node, reaching us without being received by an interface */
            assert(0);
        }
        isis_increment_event_counter(isis_event_counter_remote_new_lsp);
    }  
    
    /* Case #4 -  remote lsp with a new sequence number compared to the one in lsp database */
    else if(!self_lsp && old_lsp_pkt && (*new_seq_no < *old_seq_no))
    {
        event_type = isis_event_remote_old_lsp;
        sprintf(tlb, "\t%s : Event : %s\n", ISIS_LSPDB_TRACE, isis_event_str(event_type));
        tcp_trace(node, iif, tlb);
        if(recvd_via_intf)
        {
            /* Old lsp pkt is still in circulation, ignore it
             * Respond with the new lsp pkt found in the lspdb, only to the input interface
            */
            sprintf(tlb, "\t%s : Event : %s Old LSP %s-%u will be back fired out of intf %s\n",
                ISIS_LSPDB_TRACE, isis_event_str(event_type),
                rtr_id_str.ip_addr, *old_seq_no,
                iif->if_name);
            tcp_trace(node, iif, tlb);
            isis_queue_lsp_pkt_for_transmission(iif, old_lsp_pkt);
        }
        else{
            /* There is no way a lsp belonging to other node, reaching us without being received by an interface */
            assert(0);
        }
        isis_increment_event_counter(isis_event_counter_remote_old_lsp);
    }
    sprintf(tlb, "%s : LSPDB Updated  for new Lsp Recvd : %s-%u, old lsp : %s-%u, Event : %s\n",
        ISIS_LSPDB_TRACE,
        rtr_id_str.ip_addr, *new_seq_no,
        old_lsp_pkt ? rtr_id_str.ip_addr :0,
        old_lsp_pkt ? *old_seq_no : 0,
        isis_event_str(event_type));
    tcp_trace(node, iif, tlb); 
}
/* LSPDB timer callback handler */
static void isis_lsp_pkt_delete_from_lspdb_timer_cb(void *arg, uint32_t arg_size)
{
    if(!arg)
        return;
    isis_timer_data_t *timer_data = (isis_timer_data_t *)arg;
    node_t *node = timer_data->node;
    isis_lsp_pkt_t *lsp_pkt = (isis_lsp_pkt_t *)timer_data->data;
    timer_data->data = NULL;
    
    free(timer_data);
    timer_de_register_app_event(lsp_pkt->expiry_timer);
    lsp_pkt->expiry_timer = NULL;

    avltree_remove(&lsp_pkt->avl_node_glue, isis_get_lspdb_root(node));
    lsp_pkt->installed_in_db = false;
    isis_increment_event_counter(isis_event_counter_delete_lsp);
    isis_deref_isis_pkt(lsp_pkt);
}

void isis_start_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt)
{
    wheel_timer_t *wt;
    isis_node_info_t *node_info;
    node_info = ISIS_NODE_INFO(node);
    wt = node_get_timer_instance(node);
    if(lsp_pkt->expiry_timer)
        return;
    isis_timer_data_t *timer_data = calloc(1, sizeof(isis_timer_data_t));
    timer_data->node = node;
    timer_data->data = (byte *)lsp_pkt;
    timer_data->data_size = sizeof(isis_lsp_pkt_t);
    lsp_pkt->expiry_timer = timer_register_app_event(wt, isis_lsp_pkt_delete_from_lspdb_timer_cb, (void *)timer_data, \
                                                        sizeof(isis_timer_data_t), node_info->lsp_lifetime_interval, 0);
}

void isis_stop_lsp_pkt_installation_timer(isis_lsp_pkt_t *lsp_pkt)
{
    if(!lsp_pkt->expiry_timer)
        return;
    isis_timer_data_t *timer_data = wt_elem_get_and_set_app_data(lsp_pkt->expiry_timer, 0);
    free(timer_data);
    timer_de_register_app_event(lsp_pkt->expiry_timer);
    lsp_pkt->expiry_timer = NULL;
}

void isis_refresh_lsp_pkt_installation_timer(node_t *node, isis_lsp_pkt_t *lsp_pkt)
{
    isis_stop_lsp_pkt_installation_timer(lsp_pkt);
    isis_start_lsp_pkt_installation_timer(node, lsp_pkt);
}
