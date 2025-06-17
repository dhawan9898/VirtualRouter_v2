# VirtualRouter v2
This is an extension of the https://github.com/ebystewart/L2_Switch_L3_Router and https://github.com/ebystewart/VirtualRouter.git Projects.

- L2 Switching
    - MAC Learning
    - MAC Forwarding
    - MAC Table
    - Virtual LAN (VLAN) - No Spanning Tree Protocol implemented to prevent looping
- L3 Forwarding
- L3 routing using SPF Algorithm
    - Routing Table
- Address Resolution Protocol (ARP)
    - ARP Table
    - ARP entry with expiry timer
- Ping (minimal)
- IP-in-IP
- Notification Chain to notify subscribers of change in networkconfiguration
- Logging infrastructure to dispaly sent and received messages
- Expiry timers for dynamic ARP table
- ETH/IP Packet Generator for Testing

Useful Commands:

Show Topology: show topology
Routing table: show node R1 rt


Known Issues:

08-06-2025: Ping using IP-in-IP (i.e. ero a specific node interface) crashes due to segmentation fault - Bugfix planned
08-06-2025: Routing table using SPF is generated for only immediate neighbours (ECMP paths excluded) - Bugfix planned
08-06-2025: Ping utility to be re-tested with Dynamic routing table generation using SPF algorithm. - Planned

Solved Issues:

11-06-2025: Routing table issue for ECMP and default route fixed
11-06-2025: Ping utility (without ERO) re-tested with routing table fixes. (Ping ERO issue still exist)
