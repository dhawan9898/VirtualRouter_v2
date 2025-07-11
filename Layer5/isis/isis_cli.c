#include <assert.h>
#include "../../tcp_public.h"
#include "isis_cmdcodes.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_adjacency.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include "isis_lsdb.h"

static void isis_clear_lsp_overload_flag(void *arg, uint32_t arg_size)
{
    isis_node_info_t *node_info = (isis_node_info_t *)arg;
    UNSET_BIT(node_info->lsp_gen_flags, ISIS_LSP_F_OVERLOAD);
}

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
        else if(strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0U)
            intf_name = tlv->value;            
        else
            assert(0);
    }TLV_LOOP_END;

    node = get_node_by_node_name(topo, node_name);

    switch(cmdcode)
    {
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL:
        {
            isis_show_node_protocol_state(node);
            break;
        }
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_INTF:
        {
            intf = get_node_intf_by_name(node, intf_name);
            if(!intf){
                printf("%s: Error - Non-existing interface\n");
                return -1;
            }
            isis_show_one_intf_stats(intf);
            break;
        }
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_INTF:
        {
            isis_show_all_intf_stats(node);
            break;
        }
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB:
        {
            isis_show_lspdb(node);
            break;
        }
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP_DETAIL:
        {
            printf("%s\n", __FUNCTION__); // To be removed after test
            #if 0 // for test
            isis_node_info_t *node_info;
            if(!isis_is_protocol_enable_on_node(node))
                return;
            node_info = ISIS_NODE_INFO(node);
            isis_create_fresh_lsp_pkt(node);
            isis_lsp_pkt_t *lsp_pkt = node_info->self_lsp_pkt;
            if(!lsp_pkt)
                return;
            #else
            assert (rtr_id);
            uint32_t rtr_id_int = tcp_ip_convert_ip_p_to_n(rtr_id) ;
            isis_lsp_pkt_t *lsp_pkt = isis_lookup_lsp_entry_from_lspdb(node, rtr_id_int);
            #endif
            ethernet_frame_t *lsp_eth_hdr = (ethernet_frame_t *) (lsp_pkt->pkt);
            size_t pkt_size = lsp_pkt->pkt_size;
            isis_pkt_hdr_t *lsp_pkt_hdr = (isis_pkt_hdr_t *)(lsp_eth_hdr->payload);
            size_t lsp_pkt_size = pkt_size - GET_ETH_HDR_SIZE_EXCL_PAYLOAD(lsp_eth_hdr);
            if (!lsp_pkt) break;
            isis_show_one_lsp_pkt_detail (NULL, lsp_pkt_hdr, lsp_pkt_size);
            break;
        }
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSPDB_DETAIL:
        {
            isis_show_lspdb_detail(node); 
            break;
        }
        case CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_ADJACENCY:
        {
            isis_show_all_adjacencies(node);
            break;
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
     uint32_t overload_timer_value;
     isis_node_info_t *node_info;

     cmdcode = EXTRACT_CMD_CODE(tlv_buff);

     TLV_LOOP_BEGIN (tlv_buff, tlv) {

            if (strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0) {
                node_name = tlv->value;
            }
            else if (strncmp(tlv->leaf_id, "if-name", strlen("if-name")) == 0) {
                if_name =  tlv->value;
            }
            else if (strncmp(tlv->leaf_id, "timeout-val", strlen("timeout-val")) == 0) {
                overload_timer_value =  tlv->value;
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
     node_info = ISIS_NODE_INFO(node);

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
                case CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD:
                {
                    switch(enable_or_disable)
                    {
                        case CONFIG_ENABLE:
                            SET_BIT(node_info->lsp_gen_flags, ISIS_LSP_F_OVERLOAD);
                            break;
                        case CONFIG_DISABLE:
                            UNSET_BIT(node_info->lsp_gen_flags, ISIS_LSP_F_OVERLOAD);
                            break;
                        default:
                            ;
                    }
                    break;
                }
                case CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMER_VALUE:
                {
                    if(node_info->lsp_overload_timer)
                        return;
                    node_info->lsp_overload_timer = timer_register_app_event(node_get_timer_instance(node), isis_clear_lsp_overload_flag,\
                                                                                (void *)node_info, sizeof(isis_node_info_t), overload_timer_value, 0);
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
            {
                /* config node <node-name> protocol isis overload */
                static param_t overload;
                init_param(&overload, CMD, "overload", isis_intf_config_handler, 0, INVALID, 0, "Send overload lsp pkt");
                libcli_register_param(&isis_proto, &overload);
                set_param_cmd_code(&overload, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD);
                {
                    /* config node <node-name> protocol isis overload timeout */
                    static param_t timeout;
                    init_param(&timeout, CMD, "timeout", isis_intf_config_handler, 0, INVALID, 0, "Timeout for overloading");
                    libcli_register_param(&overload, &timeout);
                    set_param_cmd_code(&timeout, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMER);
                    {
                        /* config node <node-name> protocol isis overload timeout <timeout-val> */
                        static param_t timeout_val;
                        init_param(&timeout_val, LEAF, 0, isis_intf_config_handler, 0, 0, "timeout-val", "lsp overloading timeout value in sec");
                        libcli_register_param(&timeout, &timeout_val);
                        set_param_cmd_code(&timeout_val, CMDCODE_CONF_NODE_ISIS_PROTO_OVERLOAD_TIMER_VALUE);
                    }
                    support_cmd_negation(&overload);
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
        {
            {
                /* show node <node-name> protocol isis interface */
                static param_t interface;
                init_param(&interface, CMD, "interface",  isis_show_handler, 0, INVALID, 0, "interface");
                libcli_register_display_callback(&interface, isis_show_handler);
                libcli_register_param(&isis_proto, &interface);
                set_param_cmd_code(&interface, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_INTF);
                {
                    /* show node <node-name> protocol isis interface <if-name> */
                    static param_t if_name;
                    init_param(&if_name, LEAF, 0, isis_show_handler, 0, 0, "if-name", "Interface name");
                    libcli_register_param(&interface, &if_name);
                    set_param_cmd_code(&if_name, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_INTF);
                }
            }
            {
                /* show node <node-name> protocol isis lsdb */
                static param_t lsdb;
                init_param(&lsdb, CMD, "lsdb", isis_show_handler, 0, INVALID, 0, "lspdb");
                libcli_register_param(&isis_proto, &lsdb);
                set_param_cmd_code(&lsdb, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSDB);
                //set_param_cmd_code(&lsdb, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP_DETAIL); // For testing
                {
                    /* show node <node-name> protocol isis lsdb detail */
                    static param_t lspdb_detail;
                    init_param(&lspdb_detail, CMD, "detail", isis_show_handler, 0, INVALID, 0, "lspdb-detail");
                    libcli_register_param(&lsdb, &lspdb_detail);
                    set_param_cmd_code(&lspdb_detail, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_LSPDB_DETAIL);
                }
                {
                    static param_t rtr_id;
                    init_param(&rtr_id, LEAF, 0, isis_show_handler, 0, IPV4, "rtr-id", "Router-id in A.B.C.D format");
                    libcli_register_param(&lsdb, &rtr_id);
                    set_param_cmd_code(&rtr_id, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ONE_LSP_DETAIL);
                }
            }
            {
                /* show node <node-name> protocol isis adjacency */
                static param_t adjacency;
                init_param(&adjacency, CMD, "adjacency", isis_show_handler, 0, INVALID, 0, "adjacency");
                libcli_register_param(&isis_proto, &adjacency);
                set_param_cmd_code(&adjacency, CMDCODE_SHOW_NODE_ISIS_PROTOCOL_ALL_ADJACENCY);
            }
        }
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

