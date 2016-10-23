"""
    Printing TCP/IP classes
"""

import socket
import struct
import gen.proxies
import of10.dissector
import of13.dissector
import tcpiplib.tcpip
from gen.prints import red, green, blue, yellow, cyan


def eth_addr(a):
    """
        Print Mac Address in the human format
    Args:
        a: string "6s"
    Returns:
        mac in the human format
    """
    string = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
    mac = string % (ord(a[0]), ord(a[1]), ord(a[2]),
                    ord(a[3]), ord(a[4]), ord(a[5]))
    return mac


def get_ip_from_long(long_ip):
    """
        Get IP from a long int
    Args:
        long_ip: IP in the long int format

    Returns: IP in the format x.x.x.x
    """
    return socket.inet_ntoa(struct.pack('!L', long_ip))


def datapath_id(a):
    """
        Convert OpenFlow Datapath ID to human format
    Args:
        a: DPID in "8s" format
    Returns:
        DPID in human format
    """
    string = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
    dpid = string % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]),
                     ord(a[4]), ord(a[5]), ord(a[6]), ord(a[7]))
    return dpid


def print_headers(pkt, overwrite_min=0):
    """
        Print TCP/IP header. It uses command line option -p
            to print 'mininal' or 'full' headers
    Args:
        pkt: OFMessage class
        overwrite_min: in case of problems, overwrite user definition
    """
    if pkt.print_options['min'] == 1 and overwrite_min == 0:
        print_minimal(pkt.position, pkt.l1.time, pkt.l1.caplen, pkt.l3,
                      pkt.l4)
    else:
        print_position(pkt.position)
        print_layer1(pkt.l1.time, pkt.l1.caplen, pkt.l1.truncate)
        print_layer2(pkt.l2)
        print_layer3(pkt.l3)
        print_tcp(pkt.l4)


def print_minimal(position, date, getlen, ip, tcp):
    """
        Print TCP/IP header with minimal information
    Args:
        position: packet count
        date: date/time packet was captured
        getlen: total number of bytes captured
        ip: IP class
        tcp: TCP class
    """
    string = 'Packet #%s - %s %s:%s -> %s:%s Size: %s Bytes'

    source = gen.proxies.get_ip_name(ip.s_addr, tcp.source_port)
    dest = gen.proxies.get_ip_name(ip.d_addr, tcp.dest_port)

    print string % (position, date, cyan(source), cyan(tcp.source_port),
                    cyan(dest), cyan(tcp.dest_port), getlen)



def print_position(position):
    """
        Print the packet counter (ctr) number
    Args:
        position: number of the packet captured in the sequence
    """
    print ('Packet Number # %s' % position)


def print_layer1(date, getlen, caplen):
    """
        Prints information about the captured packet
    Args:
        date: date/time when the packet was captured
        getlen: total packet captured
        caplen: truncated size of the packet captured
    """
    print ('%s: captured %d bytes, truncated to %d bytes' %
           (date, getlen, caplen))


def print_layer2(eth):
    """
        Prints the Ethernet frame
    Args:
        eth: Ethernet class
    """
    print ('Ethernet: Destination MAC: %s Source MAC: %s Protocol: %s' %
           (eth_addr(eth.dst_mac), eth_addr(eth.src_mac),
            red(tcpiplib.tcpip.get_ethertype(eth.protocol))))


def print_vlan(vlan):
    """
        Print VLAN fields
    Args:
        vlan: VLAN class
    """
    print ('VLAN: PCP: %s CFI: %s VID: %s Protocol: %s' %
           (vlan.pcp, vlan.cfi, red(vlan.vid), hex(vlan.ethertype)))


def print_arp(arp):
    """
        Print ARP fields
    Args:
        arp: ARP class
    """
    print ('ARP: Hardware Type: %s Protocol Type: %s '
           'HW Length: %s Prot Length: %s Opcode: %s '
           '\nARP: Source MAC: %s Source IP: %s Destination MAC: %s '
           'Destination IP: %s'
           % (arp.hw_type, arp.prot_type, arp.hw_len,
              arp.prot_len, arp.opcode,
              eth_addr(arp.src_mac), get_ip_from_long(arp.src_ip),
              eth_addr(arp.dst_mac), get_ip_from_long(arp.dst_ip)))


def print_layer3(ip):
    """
        Prints IP headers
    Args:
        ip: IP class
    """
    print (('IP Version: %d IP Header Length: %d TTL: %d Protocol: %d '
           'Source Address: %s Destination Address: %s') %
           (ip.version, ip.length, ip.ttl, ip.protocol,
            blue(ip.s_addr), blue(ip.d_addr)))


def print_tcp(tcp):
    """
        Print TCP headers
    Args:
        tcp: TCP class
    """
    print ('TCP Source Port: %s Dest Port: %s Sequence Number: %s '
           'Acknowledgement: %s TCP header length: %s Flags: CWR: %s '
           'ECE: %s URG: %s ACK: %s PSH: %s RST: %s SYN: %s FYN: %s' %
           (tcp.source_port, tcp.dest_port, tcp.sequence,
            tcp.acknowledgement, tcp.length, tcp.flag_cwr,
            tcp.flag_ece, tcp.flag_urg, tcp.flag_ack, tcp.flag_psh,
            tcp.flag_rst, tcp.flag_syn, tcp.flag_fyn))


def print_openflow_header(ofp):
    """
        Print OpenFlow header
    Args:
        ofp: OFMessage class
    """
    version = tcpiplib.tcpip.get_ofp_version(ofp.version)
    name_version = '%s(%s)' % (version, ofp.version)
    if version == '1.0':
        name = of10.dissector.get_ofp_type(ofp.type)
        name_type = '%s(%s)' % (name, ofp.type)
    elif version == '1.3':
        name = of13.dissector.get_ofp_type(ofp.type)
        name_type = '%s(%s)' % (name, ofp.type)
    else:
        name_type = '%s' % ofp.type

    print ('OpenFlow Version: %s Type: %s Length: %s  XID: %s' %
           (name_version, yellow(name_type), ofp.length, red(ofp.xid)))


def print_lldp(lldp):
    """
        Print LLDP fields
    Args:
        lldp: LLDP class
    """
    if lldp.c_type is 1:
        print ('LLDP: Chassis Type(%s) Length: %s SubType: %s ID: %s' % (lldp.c_type, lldp.c_length, lldp.c_subtype,
                                                                         green(lldp.c_id)))
    if lldp.p_type is 2:
        print ('LLDP: Port Type(%s) Length: %s SubType: %s ID: %s' % (lldp.p_type, lldp.p_length, lldp.p_subtype,
                                                                      green(lldp.p_id)))
    if lldp.t_type is 3:
        print ('LLDP: TTL(%s) Length: %s Seconds: %s' % (lldp.t_type, lldp.t_length, lldp.t_ttl))

    if lldp.e_type is 0:
        print ('LLDP: END(%s) Length: %s' % (lldp.e_type, lldp.e_length))
    else:
        print ('LLDP: Malformed packet')


def print_connection_restablished(pkt):
    print_headers(pkt, overwrite_min=0)
    print(red("!!!! Attention: Connection Re-Established!!\n"))
