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

08-06-2025: Ping using IP-in-IP (i.e. ero a specific node interface) crashes due to segmentation fault - Bugfix planned (solved)
08-06-2025: Routing table using SPF is generated for only immediate neighbours (ECMP paths excluded) - Bugfix planned (solved)
08-06-2025: Ping utility to be re-tested with Dynamic routing table generation using SPF algorithm. - Planned (solved)
21-07-2025: crash during enabling trace - Bugfix planned (solved)
26-07-2025: crash while printing/tracing isis hello packets in isis_print_pkt() - Bugfix planned
29-07-2025: CLIs for hello interval update and authentication check implemented, but crashes - Bugfix planned.
30-07-2025: crash seen while attempting to refresh the expiry timer of adjacencies using resurrect_timer() API - Bugfix planned (solved)
30-07-2025: ARP table creation using Hello pkts (l2 mapping) not working - Bugfix planned
06-07-2025: Hello pkts malformed during reception whan all nodes are enabled for isis - Bugfix planned
06-07-2025: "show node R2 protocol isis adjacency" command not printing adjacency info - Bugfix planned(solved)


Solved Issues:

11-06-2025: Routing table issue for ECMP and default route fixed
11-06-2025: Ping utility (without ERO) re-tested with routing table fixes. (Ping ERO issue still exist)
13-07-2025: Ping issue with ERO is fixed now 
24-07-2025: Trace could be enabled without crash
30-07-2025: Crash seen while attempting to refresh the expiry timer is now solved
06-07-2025: "show node R2 protocol isis adjacency" command not printing adjacency info is solved now.
