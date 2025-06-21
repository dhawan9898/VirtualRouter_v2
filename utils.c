#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "utils.h"


void layer2_fill_with_broadcast_mac(char *mac_array)
{
    unsigned int i;
    for(i = 0; i < 6U; i++)
    {
        mac_array[i] = 0xFFU;
    }
}

/* apply mask on prefix and store result in str_prefix
   For eg : prefix = 122.1.1.1, mask 24, then str_prefix
   will store 122.1.1.0*/
void apply_mask(char *prefix, char mask, char *str_prefix){

    uint32_t binary_prefix = 0U;
    uint32_t subnet_mask = 0xFFFFFFFFUL;

    if(mask == 32U){
        strncpy(str_prefix, prefix, 16);
        str_prefix[15] = '\0';
        return;
    }

    /* convert given Ip address in to binary format */
    inet_pton(AF_INET, prefix, &binary_prefix);
    binary_prefix = htonl(binary_prefix);

    /* compute mask in binary format as well */
    subnet_mask = subnet_mask << (32 - mask);
    /*Perform logical AND to apply mask on IP address*/
    binary_prefix = binary_prefix & subnet_mask;

    /*Convert the Final IP into string format again*/
    binary_prefix = htonl(binary_prefix);
    inet_ntop(AF_INET, &binary_prefix, str_prefix, 16);
    str_prefix[15] = '\0';
}

/* inserts a TLV and returns the offset/index to the end of the occupied tlv buffer */
byte *tlv_buffer_insert_tlv(byte *buff, uint8_t tlv_no, uint8_t data_len, byte *data)
{
    *buff = tlv_no;
    *(buff + 1U) = data_len;
    memcpy((buff + TLV_OVERHEAD_SIZE), data, data_len);
    return (buff + TLV_OVERHEAD_SIZE + data_len);
}

byte *tlv_buffer_get_particular_tlv(byte *tlv_buff, uint32_t tlv_buff_size, uint8_t tlv_no, uint8_t *tlv_data_len)
{
    byte tlv_type;
    byte tlv_len;
    byte *tlv_value = NULL;

    ITERATE_TLV_BEGIN(tlv_buff, tlv_type, tlv_len, tlv_value, tlv_buff_size){

        if(tlv_type != tlv_no)
            continue;
        *tlv_data_len = tlv_len;
        return tlv_value;

    }ITERATE_TLV_END(tlv_buff, tlv_type, tlv_len, tlv_value, tlv_buff_size);

    *tlv_data_len = 0;
    return NULL;
}

