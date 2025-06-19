#include <assert.h>
#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"

static int isis_config_handler(param_t *param, ser_buff_t *tlv_buff, op_mode enable_or_disable)
{
    int cmdcode = -1;
    cmdcode = EXTRACT_CMD_CODE(tlv_buff);
    tlv_struct_t *tlv = NULL;
    char *node_name;
    node_t *node;

    TLV_LOOP_BEGIN(tlv_buff, tlv){

        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0U)
            node_name = tlv->value;
        else
            assert(0);
    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);

    switch(cmdcode)
    {
        case ISIS_CONFIG_NODE_ENABLE:
        {
            switch(enable_or_disable)
            {
                case CONFIG_ENABLE:
                    isis_init(node);
                    break;
                
                case CONFIG_DISABLE:
                    isis_de_init(node);
                    break;

                default:
                    ;
            }
            break;
        }
        default:
            ;
    }
    return 0;
}

static int isis_show_handler(param_t *param, ser_buff_t *tlv_buff, op_mode enable_or_disable)
{
    int cmdcode = -1;
    cmdcode = EXTRACT_CMD_CODE(tlv_buff);
    tlv_struct_t *tlv = NULL;
    char *node_name;
    node_t *node;

    TLV_LOOP_BEGIN(tlv_buff, tlv){

        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0U)
            node_name = tlv->value;
        else
            assert(0);
    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);

    switch(cmdcode)
    {
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL:
        {
            isis_show_node_protocol_state(node);
        }
        default:
            ;
    }
    return 0;
}

int isis_config_cli_tree(param_t *param){

    {
        static param_t isis_proto;
        init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
        libcli_register_param(param, &isis_proto);
        set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
    }
    return 0;
}

int isis_show_cli_tree(param_t *param){

    {
        static param_t isis_proto;
        init_param(&isis_proto, CMD, "isis", isis_show_handler, 0, INVALID, 0, "isis protocol");
        libcli_register_param(param, &isis_proto);
        set_param_cmd_code(&isis_proto, CMDCODE_SHOW_NODE_ISIS_PROTOCOL);
    }
    return 0;
}

