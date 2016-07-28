OFP_Sniffer is an OpenFlow sniffer to be used for troubleshooting and 
learning purposes.

Currently on version 0.2, it dissects all OpenFlow 1.0 messages. OpenFlow version 1.3 will 
be available on version 0.3 (to be released soon).

It works directly on Linux shell and dissects all OpenFlow messages on the 
wire. Using OFP_Sniffer, you can easily track OpenFlow messages and errors 
associated (if any), without openning X11 or Wireshark. OFP_Sniffer was 
written in Python to support the AmLight SDN deployment (www.sdn.amlight.net).
AmLight SDN uses Internet2 FlowSpace Firewall, OESS and On.Lab ONOS, and these 
apps were tested and are fully supported (well, they should be ;)).

This tool started to be developed after a conversation with Andrew Ragusa
(a.k.a. A.J) from Indiana University along the NITRD - Roadmap to Operating 
SDN-based Networks Workshop hosted by ESNET and Internet2. Thanks A.J. for your
constant support and mentoring!! (Link to NITRD workshop: https://www.nitrd.gov/nitrdgroups/index.php?title=SDN_Operational_Issues_WS)

As a command line interface tool, it has a few input parameters:
```
# ./ofp_sniffer.py -h
Usage:
 ./ofp_sniffer.py [-p min|full] [-f pcap_filter] [-F filter_file] [-i dev] [-r pcap_file]
     -p [min|full] or --print=[min|full]: print min or full packet headers. Default: min
     -f pcap_filter or --pcap-filter=pcap_filter : add a libpcap filter
     -F sanitizer_file.json or --sanitizer-file=sanitizerfile.json
     -i interface or --interface=interface. Default: eth0
     -r captured.pcap or --src-file=captured.pcap
     -o or --print-ovs : print using ovs-ofctl format
     -h or --help : prints this guidance
     -c or --no-colors: removes colors
     -v or --version : prints version

-p [min|full] gives you the option of printing minimal or full TCP/IP headers
-f pcap_filter gives you the possibility of adding libpcap filters. 
      Filter "port 6633 " is already applied. If you want to add more options, just
      add -f and the filter, for example: 
            -f " or port 6634 or host 192.168.0.2"
-F sanitizer_file.json gives you the possibility of using specific OpenFlow 
      filters, for example, ignore some OpenFlow types (PacketIn, PacketOut, 
      etc). An example is shipped with the source code
-i interface gives you the possibility of choosing the interface to sniffer. 
      Remember that you will need root powers.
-r capture.pcap gives you the possibility of working on a previously captured libpcap file.
-o gives you the possibility of printing the ovs-ofctl command that generated a
      specific flow-mod message.
```
##################### Instalation ######################
```
Required Python 2.7
apt-get install python-pcapy python-pip or yum install pcapy python-pip
pip install hexdump
git clone https://github.com/jab1982/ofp_sniffer.git
cd ofp_sniffer
sudo ./ofp_sniffer.py
```
##################### Examples #########################

Examples are provided below:
```
----------------------           -------------------------
| Mininet            |           | OVS-OFCTL 2.3.0       |
| 192.168.56.101:6634| <-------> | eth1 - 192.168.56.102 |
----------------------           -------------------------

# ovs-ofctl dump-flows tcp:192.168.56.101:6634
 cookie=0x0, duration=2183.377s, table=0, n_packets=0, n_bytes=0, idle_age=2183, in_port=1,dl_vlan=2 actions=output:2

# ./ofp_sniffer.py -i eth1 -f " or port 6634"
Sniffing device eth1
2015-09-13 11:47:38.655503 192.168.56.102:37450 -> 192.168.56.101:6634 Size: 74
OpenFlow Version: 1.0(1) Type: Hello(0) Length: 8  XID: 1
1 OpenFlow Hello

2015-09-13 11:47:38.656964 192.168.56.101:6634 -> 192.168.56.102:37450 Size: 74
OpenFlow Version: 1.0(1) Type: Hello(0) Length: 8  XID: 174
174 OpenFlow Hello

2015-09-13 11:47:38.657638 192.168.56.102:37450 -> 192.168.56.101:6634 Size: 86
OpenFlow Version: 1.0(1) Type: Vendor(4) Length: 20  XID: 2
2 OpenFlow Vendor : NICIRA(0x2320)
2 OpenFlow Vendor Data:  12  2 

2015-09-13 11:47:38.657870 192.168.56.102:37450 -> 192.168.56.101:6634 Size: 74
OpenFlow Version: 1.0(1) Type: BarrierReq(18) Length: 8  XID: 3
3 OpenFlow Barrier Request

2015-09-13 11:47:38.659270 192.168.56.101:6634 -> 192.168.56.102:37450 Size: 74
OpenFlow Version: 1.0(1) Type: BarrierRes(19) Length: 8  XID: 3
3 OpenFlow Barrier Reply

```
```
# ovs-ofctl add-flow tcp:192.168.56.101:6634 "dl_dst=10:00:00:01:20:00,dl_type=0x88bc actions=mod_vlan_vid:14,output:2"

# ./ofp_sniffer.py -i eth1 -f " or port 6634"

2015-09-13 11:49:08.171463 192.168.56.102:37451 -> 192.168.56.101:6634 Size: 154
OpenFlow Version: 1.0(1) Type: FlowMod(14) Length: 88  XID: 2
2 OpenFlow Match - wildcards: 3678439 dl_type: 0x88bc dl_dst: 10:00:00:01:20:00
2 OpenFlow Body - Cookie: 0x00 Command: Add(0) Idle/Hard Timeouts: 0/0 Priority: 32768 Buffer ID: 0xffffffff Out Port: 65535 Flags: Unknown Flag(0)
2 OpenFlow Action - Type: SetVLANID Length: 8 VLAN ID: 14 Pad: 0
2 OpenFlow Action - Type: OUTPUT Length: 8 Port: 2 Max Length: 0

# ovs-ofctl del-flows tcp:192.168.56.101:6634 "dl_type=0x88bc,dl_dst=10:00:00:01:20:00, "

# ofp_sniffer with option -o (to print ovs-ofctl command)

2015-09-13 11:50:43.636925 192.168.56.102:37454 -> 192.168.56.101:6634 Size: 138
OpenFlow Version: 1.0(1) Type: FlowMod(14) Length: 72  XID: 2
2 OpenFlow Match - wildcards: 3678439 dl_type: 0x88bc dl_dst: 10:00:00:01:20:00
2 OpenFlow Body - Cookie: 0x00 Command: Delete(3) Idle/Hard Timeouts: 0/0 Priority: 32768 Buffer ID: 0xffffffff Out Port: 65535 Flags: Unknown Flag(0)
ovs-ofctl del-flows tcp:192.168.56.101:6634 "dl_type=0x88bc,dl_dst=10:00:00:01:20:00, "

# ovs-ofctl add-flow tcp:192.168.56.101:6634 "dl_dst=10:00:00:01:20:00,dl_type=0x88bc actions=mod_vlan_vid:14,output:2"

# ofp_sniffer with option -o (to print ovs-ofctl command)

2015-09-13 11:52:58.563737 192.168.56.102:37455 -> 192.168.56.101:6634 Size: 154
OpenFlow Version: 1.0(1) Type: FlowMod(14) Length: 88  XID: 2
2 OpenFlow Match - wildcards: 3678439 dl_type: 0x88bc dl_dst: 10:00:00:01:20:00
2 OpenFlow Body - Cookie: 0x00 Command: Add(0) Idle/Hard Timeouts: 0/0 Priority: 32768 Buffer ID: 0xffffffff Out Port: 65535 Flags: Unknown Flag(0)
2 OpenFlow Action - Type: SetVLANID Length: 8 VLAN ID: 14 Pad: 0
2 OpenFlow Action - Type: OUTPUT Length: 8 Port: 2 Max Length: 0
ovs-ofctl add-flow tcp:192.168.56.101:6634 "dl_type=0x88bc,dl_dst=10:00:00:01:20:00, action=mod_vlan_vid:14,output:2,"
```

Using Filters:

When using option -F ./example_filter.json you will have a few options:

"allowed_of_versions" : used to select what OpenFlow messages you DON'T want to see. You can define different filters
   depending of the OpenFlow version
"packetIn_filter": used to define what PacketIn + LLDP messages you WANT to see. You can define per switch and/or 
   per port. For switch, you need to use the datapath_id as seen by the application you are using. For example,
   some apps fill in the field c_id with of:dpid_id, other with dpid:dpid_id. For ports, using the OpenFlow port_id,
   not the name of the port. For example, on Brocade, eth1/1 == 1. So use 1 instead of eth1/1.
  
Options PacketOut_filter and flowMod_logs are not deployed yet (future use).

Support for OpenFlow proxies:

When using an OpenFlow proxy, depending of the interface you select to sniffer, you are going to see one of the two
   possibilities:

   IP_Controller <-> IP_Proxy
   IP_Proxy <-> IP_Switch

It is hard to associate which controller is talking to which switch. To ease this troubleshooting, the OpenFlow 
   sniffer automatically monitors all PacketOut + LLDP messages to create a dictionary of {IP:port, name_switch}.
   If this is your case, change the file ofp_fsfw_v10.py, under the variable "name" with the DPID and name of 
   each switch. Next time you run the sniffer, you are going to see the IP and between paranthesys the device behind 
   the proxy. Example:

```
2015-12-16 15:37:41.563621 200.0.207.79(andes1):7801 -> 190.103.184.135:6633 Size: 157 Bytes
OpenFlow Version: 1.0(1) Type: PacketIn(10) Length: 103  XID: 0
0 PacketIn: buffer_id: 0xffffffff total_len: 85 in_port: 49 reason: OFPR_NO_MATCH(0) pad: 0
0 Ethernet: Destination MAC: ff:ff:ff:ff:ff:ff Source MAC: de:ad:be:ef:ba:11 Protocol: 0x8100
0 Ethernet: Prio: 0 CFI: 0 VID: 3720
0 LLDP: Chassis Type(1) Length: 7 SubType: 4 ID: of:cc4e249102000000
0 LLDP: Port Type(2) Length: 5 SubType: 2 ID: 2
0 LLDP: TTL(3) Length: 2 Seconds: 120
0 LLDP: END(0) Length: 0

2015-12-16 15:37:41.564414 190.103.184.133(andes1):56132 -> 190.103.187.72:6633 Size: 165 Bytes
OpenFlow Version: 1.0(1) Type: PacketIn(10) Length: 99  XID: 0
0 PacketIn: buffer_id: 0xffffffff total_len: 81 in_port: 49 reason: OFPR_NO_MATCH(0) pad: 0
0 Ethernet: Destination MAC: ff:ff:ff:ff:ff:ff Source MAC: de:ad:be:ef:ba:11 Protocol: 0x8942
0 LLDP: Chassis Type(1) Length: 7 SubType: 4 ID: of:cc4e249102000000
0 LLDP: Port Type(2) Length: 5 SubType: 2 ID: 2
0 LLDP: TTL(3) Length: 2 Seconds: 120
0 LLDP: END(0) Length: 0
```

The name (andes1) represents a switch called "andes1" with DPID cc4e249126000000. Not that the DPID showed in the 
  example is not the same, because a PacketIn message is being used as an example. PacketIn shows the DPID of the 
  neighbors of "andes1". 

I hope this code helps you. This is the second version, a few changes are already planned for 0.3. Coming soon!

Questions/Suggestions: Jeronimo Bezerra <jab@amlight.net>

