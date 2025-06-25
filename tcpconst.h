#ifndef TCP_CONST_H
#define TCP_CONST_H

/* Specified in ethernet_frame->type */
#define ARP_BROAD_REQ   1
#define ARP_REPLY       2
#define ARP_MSG         806
#define BROADCAST_MAC   0xFFFFFFFFFFFF
#define ETH_IP          0x0800
#define ICMP_PRO        1
#define ICMP_ECHO_REQ   8
#define ICMP_ECHO_REP   0
#define MTCP            20
#define USERAPP1        21
#define VLAN_8021Q_PROTO    0x8100
#define IP_IN_IP        4

#define MAX_NXT_HOPS        4



#define IP_HDR_INCLUDED         (1 << 0)
#define DATA_LINK_HDR_INCLUDED  (1 << 1)

#define INTF_METRIC_DEFAULT           14

#define PKT_BUFFER_RIGHT_ROOM        128

#define TCP_LOG_BUFFER_LEN	256
#define MAX_PACKET_BUFFER_SIZE 2048U
#define NODE_PRINT_BUFF_LEN 2048U

#endif