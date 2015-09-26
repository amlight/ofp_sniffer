OFP_Sniffer is an OpenFlow sniffer to be used for troubleshooting and 
learning purposes.

Currently on version 0.1, it dissects only OpenFlow 1.0 messages, but it 
prints all OpenFlow messages, independently of version. Version 1.3 will 
be dissected soon. 

It works directly on Linux shell and dissects all OpenFlow messages on the 
wire. Using OFP_Sniffer, you can easily track OpenFlow 1.0 types Hello, 
BarrierReq, BarrierRes, FlowMod, Vendor and FlowRemoved messages and errors 
associated (if any), without openning X11 or Wireshark. OFP_Sniffer was 
written in Python to support the AmLight SDN deployment (www.sdn.amlight.net).
AmLight SDN uses Internet2 FlowSpace Firewall, OESS and On.Lab ONOS, and these 
apps were tested and are fully supported (well, they should be ;)).

This tool started to be developed after a conversation with Andrew Ragusa
(a.k.a. A.J) from Indiana University after the NITRD - Roadmap for an 
Operational SDN Workshop hosted by ESNET and Internet2. Thanks A.J. for your
constant support and mentoring!! (Link to NITRD workshop: https://www.nitrd.gov/nitrdgroups/index.php?title=SDN_Operational_Issues_WS)

Currently, the following OpenFlow 1.0 messages are dissected:

  Hello 
  Error
  Vendor
  FlowRemoved
  FlowMod
  BarrierReq
  BarrierRes

Sooner types StatsReq, StatsRes, FeatureReq, FeatureRes, GetConfigReq, 
GetConfigRes, SetConfig, PortMod, EchoReq and EchoRes will be dissected. They
were not dissected on first version because, from the troubleshooting point of
view, they weren't needed.

As a command line interface tool, it has a few input parameters:
```
# ./ofp_sniffer.py -h
Usage: 
./ofp_sniffer.py [-p min|full] [-f pcap_filter] [-F filter_file] [-i dev] [-r pcap_file] 
     -p [min|full] or --print=[min|full]: print min or full packet headers. Default: min
     -f pcap_filter or --pcap-filter=pcap_filter : add a libpcap filter
     -F sanitizer_file.json or --sanitizer-file=sanitizer_file.json
     -i interface or --interface=interface. Default: eth0
     -r captured.pcap or --src-file=captured.pcap
     -o or --print-ovs : print using ovs-ofctl add-flows format
     -h or --help

-p [min|full] gives you the option of printing minimal or full TCP/IP headers
-f pcap_filter gives you the possibility of adding libpcap filters. 
      Filter "port 6633 " is already sent. If you want to add more options. Just
      add -f " or port X or host IP.IP.IP.IP "
-F sanitizer_file.json gives you the possibility of using specific OpenFlow 
      filters, for example, ignore some OpenFlow types (PacketIn, PacketOut, 
      etc). An example is ship with the source code
-i interface gives you the possibility of choosing the listing interface. 
      Remember that you will need root powers.
-r capture.pcap gives you the possibility of working on a captured libpcap file.
      This option is not functional yet
-o gives you the possibility of printing the ovs-ofctl command that generated a
      specific flow-mod message.
```
##################### Instalation ######################
```
apt-get install python-pcapy or yum install pcapy
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

2015-09-13 11:47:38.659689 192.168.56.102:37450 -> 192.168.56.101:6634 Size: 98
OpenFlow Version: 1.0(1) Type: StatsReq(16) Length: 32  XID: 4
4 OpenFlow OFP_Type 16 not dissected 

2015-09-13 11:47:38.660940 192.168.56.101:6634 -> 192.168.56.102:37450 Size: 162
OpenFlow Version: 1.0(1) Type: StatsRes(17) Length: 96  XID: 4
4 OpenFlow OFP_Type 17 not dissected 
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

I hope this code helps you. This is the first version, a few changes are already planned for 0.2. Coming soon!

Questions/Suggestions: Jeronimo Bezerra <jab@amlight.net>

