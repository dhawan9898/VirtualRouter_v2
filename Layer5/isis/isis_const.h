#ifndef _ISIS_CONST_H
#define _ISIS_CONST_H

#define ISIS_ETH_PKT_TYPE               131
#define ISIS_PTP_HELLO_PKT_TYPE          17
#define ISIS_LSP_PKT_TYPE                18
#define ISIS_DEFAULT_HELLO_INTERVAL       3
#define ISIS_ADJ_DEFAULT_DELETE_TIME      5
#define ISIS_DEFAULT_INTF_COST           10  // as per standard


/*ISIS TLVs */
#define ISIS_TLV_HOSTNAME               137  // as per standard 
#define ISIS_TLV_RTR_ID                 134  // as per standard 
#define ISIS_TLV_IF_IP                  132  // as per standard
#define ISIS_TLV_IF_MAC                 131  // Imaginary
#define ISIS_TLV_HOLD_TIME                5
#define ISIS_TLV_METRIC_VAL               6
#define ISIS_TLV_IF_INDEX                 4  // as per standard
#define ISIS_TLV_MAC_ADDR               112

#define ISIS_IS_REACH_TLV  22 // as per standard 0
#define ISIS_TLV_LOCAL_IP   6 // as per standard
#define ISIS_TLV_REMOTE_IP  8 // as per standard

#define ISIS_TLV_ON_DEMAND 111

#define ISIS_HOLD_TIME_FACTOR 2

#define ISIS_CONFIG_TRACE   "ISIS(CONFIG)"

#endif