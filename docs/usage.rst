Usage
=====

As a command line interface tool, it has a few input parameters:

.. code:: shell

  ./ofp_sniffer.py -h

  Usage:
   ./ofp_sniffer.py [-p min|full] [-f pcap_filter] [-F filter_file] [-i dev] [-r pcap_file]
           -p : print all TCP/IP headers. Default: min
           -f pcap_filter or --pcap-filter=pcap_filter: add a libpcap filter
           -F filters_file.json or --filters-file=filters.json
           -i interface or --interface=interface. Default: eth0
           -r captured.pcap or --src-file=captured.pcap
           -T topology.json or --topology-file=topology.json
           -w file or --save-to-file=file: save output to file provided    -o or --print-ovs : print using ovs-ofctl format
           -h or --help : prints this help
           -c or --no-colors: removes colors
           -q or --no-output: disables output to std_out
           -v or --version : prints version
           -O WARN:CRIT or --oess-fvd=WARN:CRIT: monitor OESS FVD status
           -S or --enable-statistics: creates statistics
           -I or --enable-influx: enables influxdb. Only works if -S is enabled

CLI Options
-----------

Examples are provided below, with this topology:

.. code:: shell

  ----------------------           -------------------------
  | Mininet            |           | OVS-OFCTL 2.3.0       |
  | 192.168.56.101:6634| <-------> | eth1 - 192.168.56.102 |
  ----------------------           -------------------------

   ovs-ofctl dump-flows tcp:192.168.56.101:6634
   cookie=0x0, duration=2183.377s, table=0, n_packets=0, n_bytes=0, idle_age=2183, in_port=1,dl_vlan=2 actions=output:2


Sniffing on interface `eth1` and filtering for TCP port 6634:

.. code:: shell

  ./ofp_sniffer.py -i eth1 -f " or port 6634"

Output:

.. code:: shell

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

Using Filters, when using option `-F` ./filters.json you will have a few options:


- `rejected_of_types` : used to select what OpenFlow message types you DON'T want to see. You can define different filters depending of the OpenFlow version

- `ethertypes`, filters by Ethertype: If you are looking for a specific Ethertype being transported by PacketOut or PacketIn messages, you can reject all others, giving you easy visualization.

- `packetIn_filter`: used to define what PacketIn + LLDP messages you WANT to see. You can define per switch and/or per port. For switch, you need to use the datapath_id as seen by the application you are using. For example, some apps fill in the field c_id with of:dpid_id, other with dpid:dpid_id. For ports, using the OpenFlow port_id, not the port name. For example, on Brocade, eth1/1 == 1. So use 1 instead of eth1/1.

- `packetOut_filter`: used to define what PacketOut + LLDP messages you WANT to see. You can define per switch and/or per port. For switch, you need to use the datapath_id as seen by the application you are using. For example, some apps fill in the field c_id with of:dpid_id, other with dpid:dpid_id. For ports, using the OpenFlow port_id, not the name of the port. For example, on Brocade, eth1/1 == 1. So use 1 instead of eth1/1.

The following snippet shows a typical usage of these filters:

.. code:: shell

    "filters":{
        "ethertypes": {
            "lldp" : 0,
            "fvd"  : 0,
            "arp"  : 1,
            "others": [ "88b5" ]
        },
        "packetIn_filter": {
            "switch_dpid": "any",
            "in_port": "any"
        },
        "packetOut_filter": {
            "switch_dpid": "any",
            "out_port": "any"
        }
    }

.. note::

    In the ethertype dictionary, 1 means filter, 0 means print it. In this example provided, ARP messages won't be seen, while OESS FVD and LLDP will. You can add the Ethertype hex number (without the 0x) in the "others" section, just adding commas (",").

Example of OpenFlow proxies
---------------------------

When using an OpenFlow proxy, depending of the interface you select to sniffer, you are going to see one of the two possibilities:

1.   IP_Controller <-> IP_Proxy
2.   IP_Proxy <-> IP_Switch

It is hard to associate which controller is talking to which switch. To ease this troubleshooting, the OpenFlow sniffer automatically monitors all PacketOut + LLDP messages to create a dictionary of {(IP, port): name_switch}. If this is your case, change the file docs/topology.json. Next time you run the sniffer, you are going to see the IP and between parentheses the device behind the proxy. Example:


.. code:: shell

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

The name (andes1) represents a switch called "andes1" with DPID cc4e249126000000. Note that the DPID showed in the example is not the same, because a PacketIn message is being used as an example. PacketIn shows the DPID of the neighbors of "andes1".
