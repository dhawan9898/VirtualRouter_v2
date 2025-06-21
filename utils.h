#ifndef UTILS_H
#define UITLS_H

#include <stdint.h>

typedef unsigned char byte;

/* bit operations */
#define SET_BIT(var, pos)       (var | (1U << pos))
#define IS_BIT_SET(var, pos)    ((var & (1U << pos)) == 1U)

#define IS_MAC_BROADCAST_ADDR(mac) \
       (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF && \
        mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF)

#define TLV_OVERHEAD_SIZE  2 /* 1 Byte Type and 1 Byte length */

/*Macro to Type Length Value reply
 * byte * - start_ptr, IN
 * unsigned char - type, OUT
 * unsigned char - length, OUT
 * unsigned char * - tlv_ptr, OUT
 * unsigned int - total_size(excluding first 8 bytes), IN
 * */
#define ITERATE_TLV_BEGIN(start_ptr, type, length, tlv_ptr, tlv_size)                                                   \
{                                                                                                                       \
        unsigned int _len = 0;                                                                                          \
        unsigned char _tlv_value_size = 0;                                                                              \
        type = 0;                                                                                                       \
        length = 0;                                                                                                     \
        tlv_ptr = NULL;                                                                                                 \
        for(tlv_ptr = (unsigned char *)start_ptr + TLV_OVERHEAD_SIZE;                                                   \
                _len < tlv_size;                                                                                        \
                _len += _tlv_value_size + TLV_OVERHEAD_SIZE,                                                            \
                tlv_ptr = (tlv_ptr + TLV_OVERHEAD_SIZE + length)){                                                      \
                        type = *(tlv_ptr - TLV_OVERHEAD_SIZE);                                                          \
                        _tlv_value_size = (unsigned char)(*(tlv_ptr - TLV_OVERHEAD_SIZE + sizeof(unsigned char)));      \
                        length = _tlv_value_size;                                                                       \
                
#define ITERATE_TLV_END(start_ptr, type, length, tlv_ptr, tlv_size)                                                     \
        }}


void layer2_fill_with_broadcast_mac(char *mac_array);

void apply_mask(char *prefix, char mask, char *str_prefix);

byte *tlv_buffer_insert_tlv(byte *buff, uint8_t tlv_no, uint8_t data_len, byte *data);

byte *tlv_buffer_get_particular_tlv(byte *tlv_buff, uint32_t tlv_buff_size, uint8_t tlv_no, uint8_t *tlv_data_len);

#endif  //UTILS_H