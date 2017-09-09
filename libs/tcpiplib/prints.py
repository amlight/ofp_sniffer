"""
    Printing TCP/IP classes
"""
import socket
import struct
from datetime import datetime
import libs.openflow.of10.dissector
import libs.tcpiplib.tcpip
from libs.core.printing import PrintingOptions
from libs.gen.prints import red, green, blue, yellow, cyan
from libs.tcpiplib.tcpip import get_ethertype
from apps.ofp_proxies import OFProxy


def eth_addr(a):
    """
        Print Mac Address in the human format
    Args:
        a: string "6s"
    Returns:
        mac in the human format
    """
    if isinstance(a, bytes):
        a = a.decode("latin")
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
    if isinstance(a, bytes):
        a = a.decode("latin")
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
    if PrintingOptions().is_minimal_headers() and overwrite_min == 0:
        print_minimal(pkt.position, pkt.l1.time, pkt.l1.caplen, pkt.l3,
                      pkt.l4)
    else:
        print_position(pkt.position)
        print_layer1(pkt.l1.time, pkt.l1.caplen, pkt.l1.truncate)
        print_layer2(pkt.l2)
        print_layer3(pkt.l3)
        print_tcp(pkt.l4)


def print_minimal(position, date, getlen, ip_addr, tcp):
    """
        Print TCP/IP header with minimal information
    Args:
        position: packet count
        date: date/time packet was captured
        getlen: total number of bytes captured
        ip_addr: IP class
        tcp: TCP class
    """
    string = 'Packet #%s - %s %s:%s -> %s:%s Size: %s Bytes'

    source = OFProxy().get_name(ip_addr.s_addr, tcp.source_port)
    dest = OFProxy().get_name(ip_addr.d_addr, tcp.dest_port)

    print(string % (position, date, cyan(source), cyan(tcp.source_port),
                    cyan(dest), cyan(tcp.dest_port), getlen))


def print_position(position):
    """
        Print the packet counter (ctr) number
    Args:
        position: number of the packet captured in the sequence
    """
    print('Packet Number # %s' % position)


def print_layer1(date, getlen, caplen):
    """
        Prints information about the captured packet
    Args:
        date: date/time when the packet was captured
        getlen: total packet captured
        caplen: truncated size of the packet captured
    """
    print('%s: captured %d bytes, truncated to %d bytes' %
          (date, getlen, caplen))


def print_layer2(eth):
    """
        Prints the Ethernet frame
    Args:
        eth: Ethernet class
    """
    print('Ethernet: Destination MAC: %s Source MAC: %s Protocol: %s' %
          (eth_addr(eth.dst_mac), eth_addr(eth.src_mac),
           red(libs.tcpiplib.tcpip.get_ethertype(eth.protocol))))


def print_vlan(vlan):
    """
        Print VLAN fields
    Args:
        vlan: VLAN class
    """
    print('VLAN: PCP: %s CFI: %s VID: %s Protocol: %s' %
          (vlan.pcp, vlan.cfi, red(vlan.vid),
           red(get_ethertype(vlan.ethertype))))


def print_arp(arp):
    """
        Print ARP fields
    Args:
        arp: ARP class
    """
    print('ARP: Hardware Type: %s Protocol Type: %s '
          'HW Length: %s Prot Length: %s Opcode: %s '
          '\nARP: Source MAC: %s Source IP: %s Destination MAC: %s '
          'Destination IP: %s'
          % (arp.hw_type, arp.prot_type, arp.hw_len,
             arp.prot_len, arp.opcode,
             eth_addr(arp.src_mac), get_ip_from_long(arp.src_ip),
             eth_addr(arp.dst_mac), get_ip_from_long(arp.dst_ip)))


def print_layer3(ip_addr):
    """
        Prints IP headers
    Args:
        ip: IP class
    """
    print(('IP Version: %d IP Header Length: %d TTL: %d Protocol: %d '
           'Source Address: %s Destination Address: %s') %
          (ip_addr.version, ip_addr.length, ip_addr.ttl, ip_addr.protocol,
           blue(ip_addr.s_addr), blue(ip_addr.d_addr)))


def print_tcp(tcp):
    """
        Print TCP headers
    Args:
        tcp: TCP class
    """
    print('TCP Source Port: %s Dest Port: %s Sequence Number: %s '
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
    version = libs.tcpiplib.tcpip.get_ofp_version(ofp.header.version.value)
    name_version = '%s(%s)' % (version, ofp.header.version.value)

    name = "%s" % ofp.header.message_type
    name_type = '%s(%s)' % (name.split('.')[1], ofp.header.message_type.value)

    print('OpenFlow Version: %s Type: %s Length: %s  XID: %s' %
          (name_version, yellow(name_type), ofp.header.length, red(ofp.header.xid)))


def print_lldp(lldp):
    """
        Print LLDP fields
    Args:
        lldp: LLDP class
    """
    if lldp.c_type is not 1 or lldp.p_type is not 2 \
            or lldp.t_type is not 3 or lldp.e_type is not 0:
        print('LLDP: Malformed packet')
        return

    if lldp.c_type is 1:
        print('LLDP: Chassis Type(%s) Length: %s SubType: %s ID: %s' %
              (lldp.c_type, lldp.c_length, lldp.c_subtype, green(lldp.c_id)))
    if lldp.p_type is 2:
        print('LLDP: Port Type(%s) Length: %s SubType: %s ID: %s' %
              (lldp.p_type, lldp.p_length, lldp.p_subtype, green(lldp.p_id)))
    if lldp.t_type is 3:
        print('LLDP: TTL(%s) Length: %s Seconds: %s' %
              (lldp.t_type, lldp.t_length, lldp.t_ttl))

    if lldp.e_type is 0:
        print('LLDP: END(%s) Length: %s' % (lldp.e_type, lldp.e_length))


def print_oessfvd(fvd):
    """
        Print FVD fields
        Args:
            fvd: OessFvd class
    """
    timestamp = str(datetime.fromtimestamp(fvd.timestamp))
    print('OESS FVD: %s:%s -> %s:%s time: %s' %
          (red(fvd.side_a), blue(fvd.port_a), red(fvd.side_z), blue(fvd.port_z),
           blue(timestamp)))


def print_connection_restablished(pkt):
    """
        Just prints that the TCP connection was restablished.
        Args:
            pkt: Packet class
    """
    print_headers(pkt, overwrite_min=0)
    print(red("!!!! Attention: Connection Re-Established!!\n"))
