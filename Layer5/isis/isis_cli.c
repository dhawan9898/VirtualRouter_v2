#include <assert.h>
#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_const.h"

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
    tlv_struct_t *tlv = NULL;
    char *node_name;
    node_t *node;
    char *rtr_id = NULL;
    interface_t *intf = NULL;
    char *intf_name = NULL;

    cmdcode = EXTRACT_CMD_CODE(tlv_buff);

    TLV_LOOP_BEGIN(tlv_buff, tlv){

        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0U)
            node_name = tlv->value;
        else if(strncmp(tlv->leaf_id, "rtr-id", strlen("rtr-id")) == 0U)
            rtr_id = tlv->value;
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

static int isis_intf_config_handler(param_t *param, ser_buff_t *tlv_buff, op_mode enable_or_disable) {

     int cmdcode = - 1;
     tlv_struct_t *tlv = NULL;
     char *node_name = NULL;
     node_t *node;
     char *if_name = NULL;
     interface_t *interface = NULL;
     uint32_t hello_interval;
     uint32_t passcode;

     cmdcode = EXTRACT_CMD_CODE(tlv_buff);

     TLV_LOOP_BEGIN (tlv_buff, tlv) {

            if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
                node_name = tlv->value;
            }
            else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0) {
                if_name =  tlv->value;
            }
            #if ISIS_ENABLE_AUTH   
            else if (strncmp(tlv->leaf_id, "hello-interval-value", strlen("hello-interval-value")) == 0){
                hello_interval = tlv->value;
            }  
            else if (strncmp(tlv->leaf_id, "passcode", strlen("passcode")) == 0){
                memcpy(&ISIS_INTF_AUTH_PASSCODE(interface), tlv->value, 32);
            }
            #endif
            else {
                assert(0);
            }
     } TLV_LOOP_END;

     node = get_node_by_node_name(topo, node_name);

     switch (cmdcode) {

         case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE:
            switch (enable_or_disable) {

                /* config node <node-name> protocol isis interface all */
                case CONFIG_ENABLE:

                   ITERATE_NODE_INTERFACES_BEGIN(node, interface) {
                       
                         isis_enable_protocol_on_interface(interface);

                   }ITERATE_NODE_INTERFACES_END(node, interface) 

                break;
                /* config node <node-name> [no] protocol isis interface all */
                case CONFIG_DISABLE:

                   ITERATE_NODE_INTERFACES_BEGIN(node, interface) {
                     
                       isis_disable_protocol_on_interface(interface);

                   } ITERATE_NODE_INTERFACES_END(node, interface)
                   break;
                /* cofig node <node-name> protocol isis interface <if-name> hello-interval <hello-interval-value> */
                case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_HELLO_INTERVAL:
                {
                    if((hello_interval > 100) && (hello_interval < 3)){
                        assert(0);
                    }
                    interface = get_node_intf_by_name(node, if_name);
                    ISIS_INTF_HELLO_INTERVAL(interface) = hello_interval;
                    break;
                }
                /* cofig node <node-name> protocol isis interface <if-name> authentication <passcode> */
                case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_AUTH:
                {
                    interface = get_node_intf_by_name(node, if_name);
                    #if ISIS_ENABLE_AUTH   
                    ISIS_INTF_IS_AUTH_ENABLED(interface) = true;
                    #endif
                    break;
                }
                /* cofig node <node-name> protocol isis layer2-map */
                case CMDCODE_CONF_NODE_ISIS_PROTO_L2_MAP:
                {
                    isis_enable_layer2_mapping(node);
                    break;
                }
                default: ;
            }
            break;
            case CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE:
                
                interface = get_node_intf_by_name(node, if_name);
                if (!interface) {
                    printf("%s: Error - Interface do not exist\n", __FUNCTION__);
                    return -1;
                }

                switch (enable_or_disable) {
                    /* config node <node-name> protocol isis interface <if-name> */
                    case CONFIG_ENABLE:
                        isis_enable_protocol_on_interface(interface);
                    break;
                    /* config node <node-name> [no] protocol isis interface <if-name> */
                    case CONFIG_DISABLE:
                        isis_disable_protocol_on_interface(interface);
                    break;
                    default: ;
                }
            break;
     }

     return 0;
}
/* clear node <node-name> protocol isis */
int isis_clear_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable)
{
    node_t *node;
    tlv_struct_t *tlv;
    bool regen_lsp = false;
    isis_adjacency_t *adjacency;
    char *node_name = NULL;

    int cmdcode = EXTRACT_CMD_CODE(tlv_buf);

    TLV_LOOP_BEGIN(tlv_buf, tlv){
        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0U)
            node_name = tlv->value;
        else
            assert(0);
    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);
    switch(cmdcode){

        case CMDCODE_CLEAR_NODE_ISIS_ADJACENCY:
        {
            interface_t *intf;
            ITERATE_NODE_INTERFACES_BEGIN(node, intf){

                if(!isis_node_intf_is_enable(intf))
                    continue;
                adjacency = ISIS_INTF_INFO(intf)->adjacency;
                if(!adjacency)
                    continue;
                if(adjacency->adj_state == ISIS_ADJ_STATE_UP){
                    regen_lsp = true;
                }
                isis_delete_adjacency(adjacency);
            }ITERATE_NODE_INTERFACES_END(node, intf);
            break;
        }
        case CMDCODE_CLEAR_NODE_ISIS_LSDB:
        {

            break;
        }
    }
}

int isis_config_cli_tree(param_t *param){

    {
        /* config node <node-name> protocol isis */
        static param_t isis_proto;
        init_param(&isis_proto, CMD, "isis", isis_config_handler, 0, INVALID, 0, "isis protocol");
        libcli_register_param(param, &isis_proto);
        set_param_cmd_code(&isis_proto, ISIS_CONFIG_NODE_ENABLE);
        {
            {
                /* config node <node-name> protocol isis layer2-map */
                static param_t l2map;
                init_param(&l2map, CMD, "layer2-map", isis_intf_config_handler, 0, INVALID, 0, "Layer 2 Mapping");
                libcli_register_param(&isis_proto, &l2map);
                set_param_cmd_code(&l2map, CMDCODE_CONF_NODE_ISIS_PROTO_L2_MAP);
                {
                    support_cmd_negation(&l2map);
                }
            }

            /* config node <node-name> protocol isis interface ...*/
            static param_t interface;
            init_param(&interface, CMD, "interface", 0, 0, INVALID, 0, "interface");
            libcli_register_param(&isis_proto, &interface);
            {
                 /* config node <node-name> protocol isis interface all*/
                  static param_t all;
                 init_param(&all, CMD, "all", isis_intf_config_handler, 0, INVALID, 0, "all Interfaces");
                 libcli_register_param(&interface, &all);
                 set_param_cmd_code(&all, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ALL_ENABLE);
            }
            {
                /* config node <node-name> protocol isis interface <if-name>*/
                static param_t if_name;
                init_param(&if_name, LEAF, 0, isis_intf_config_handler, 0, STRING, "if-name", "interface name");
                libcli_register_param(&interface, &if_name);
                set_param_cmd_code(&if_name, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_ENABLE);
                #if ISIS_ENABLE_AUTH  
                {
                    /* config node <node-name> protocol isis interface <if-name> hello-interval */
                    static param_t hello_interval;
                    init_param(&hello_interval, CMD, "hello-interval", isis_intf_config_handler, 0, INVALID, 0, "hello interval config");
                    libcli_register_param(&interface, &hello_interval);
                    set_param_cmd_code(&hello_interval, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_HELLO_INTERVAL);
                    {
                        /* config node <node-name> protocol isis interface <if-name> hello-interval <hello-interval-value> */
                        static param_t hello_interval_value;
                        init_param(&hello_interval_value, LEAF, 0, isis_intf_config_handler, 0, STRING, "hello-interval-value", "hello interval value");
                        libcli_register_param(&interface, &hello_interval_value);
                        set_param_cmd_code(&hello_interval_value, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_HELLO_INTERVAL_VALUE);
                    }
                }

                {
                    /* config node <node-name> protocol isis interface <if-name> hello-interval <hello-interval-value> */
                    static param_t authentication;
                    init_param(&authentication, CMD, "authentication", isis_intf_config_handler, 0, INVALID, 0, "authentication");
                    libcli_register_param(&interface, &authentication);
                    set_param_cmd_code(&authentication, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_AUTH);
                    {
                        /* config node <node-name> protocol isis interface <if-name> hello-interval <hello-interval-value> */
                        static param_t passcode;
                        init_param(&passcode, LEAF, 0, isis_intf_config_handler, 0, STRING, "passcode", "passcode");
                        libcli_register_param(&interface, &passcode);
                        set_param_cmd_code(&passcode, CMDCODE_CONF_NODE_ISIS_PROTO_INTF_AUTH_PASSCODE);
                    }
                }
                #endif
            }
        }
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

int isis_clear_cli_tree(param_t *param){

    {
        /* clear node <node-name> protocol ....*/
        static param_t isis_proto;
        init_param(&isis_proto, CMD, "isis", 0, 0, INVALID, 0, "isis protocol");
        libcli_register_param(param, &isis_proto);

        {
            /*clear node <node-name> protocol isis adjacency */
            static param_t adjacency;
            init_param(&adjacency, CMD, "adjacency", isis_clear_handler, 0, INVALID, 0, "isis adjacency");
            libcli_register_param(&isis_proto, &adjacency);
            set_param_cmd_code(&adjacency, CMDCODE_CLEAR_NODE_ISIS_ADJACENCY);
        }

        {
            /* clear node <node-name> protocol isis lsdb */
            static param_t lsdb;
            init_param(&lsdb, CMD, "lsdb", isis_clear_handler, 0, INVALID, 0, "lsdb");
            libcli_register_param(&isis_proto, &lsdb);
            set_param_cmd_code(&lsdb, CMDCODE_CLEAR_NODE_ISIS_LSDB);
        }
    }
    return 0;
}

