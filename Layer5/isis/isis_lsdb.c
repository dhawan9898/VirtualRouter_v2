#include "../../tcp_public.h"
#include "isis_lsdb.h"
#include "isis_pkt.h"
#include "isis_const.h"


void isis_schedule_lsp_pkt_generation(node_t *node)
{
    
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