'''
    Generic/Protocol-independent prints
'''

from gen.termcolor import colored
import of10.dissector
import of13.dissector
import gen.cli  # NO_COLOR variable
import gen.proxies
import socket
import struct
import gen.tcpip


def debug(pkt, string):
    if pkt.print_options['debug'] is 1:
        print 'DEBUG: %s' % string


def red(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'red')


def green(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'green')


def blue(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'blue')


def yellow(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'yellow')


def cyan(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'cyan')


def eth_addr(a):
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]),
                                             ord(a[3]), ord(a[4]), ord(a[5]))
    return mac


def datapath_id(a):
    dpid = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]),
                                                        ord(a[2]), ord(a[3]),
                                                        ord(a[4]), ord(a[5]),
                                                        ord(a[6]), ord(a[7]))
    return dpid


def get_ip_from_long(long_ip):
    return (socket.inet_ntoa(struct.pack('!L', long_ip)))


def print_headers(pkt):
    if pkt.print_options['min'] == 1:
        print_minimal(pkt.position, pkt.l1['time'], pkt.l1['caplen'], pkt.l3,
                      pkt.l4)
    else:
        print_position(pkt.position)
        print_layer1(pkt.l1['time'], pkt.l1['caplen'], pkt.l1['truncate_len'])
        print_layer2(pkt.l2)
        print_layer3(pkt.l3)
        print_tcp(pkt.l4)


def print_minimal(position, date, getlen, ip, tcp):
    string = 'Packet #%s - %s %s:%s -> %s:%s Size: %s Bytes'

    source = gen.proxies.get_ip_name(ip['s_addr'], tcp['source_port'])
    dest = gen.proxies.get_ip_name(ip['d_addr'], tcp['dest_port'])

    print string % (position, date, cyan(source), cyan(tcp['source_port']),
                    cyan(dest), cyan(tcp['dest_port']), getlen)


def print_position(position):
    print ('Position # %s' % position)


def print_layer1(date, getlen, caplen):
    print ('%s: captured %d bytes, truncated to %d bytes' %
           (date, getlen, caplen))


def print_layer2(eth):
    print ('Ethernet: Destination MAC: %s Source MAC: %s Protocol: %s' %
           (eth_addr(eth['dst_mac']), eth_addr(eth['src_mac']),
            red(gen.tcpip.get_ethertype(eth['protocol']))))


def print_vlan(vlan):
    print ('VLAN: Prio: %s CFI: %s VID: %s' %
           (vlan['prio'], vlan['cfi'], red(vlan['vid'])))


def print_arp(arp):
    print ('ARP: Hardware Type: %s Protocol Type: %s '
           'HW Length: %s Prot Length: %s Opcode: %s '
           '\nARP: Source MAC: %s Source IP: %s Destination MAC: %s '
           'Destination IP: %s'
           % (arp['hw_type'], arp['prot_type'], arp['hw_len'], arp['prot_len'],
              arp['opcode'],
              eth_addr(arp['src_mac']), get_ip_from_long(arp['src_ip']),
              eth_addr(arp['dst_mac']), get_ip_from_long(arp['dst_ip'])))


def print_layer3(ip):
    print (('IP Version: %d IP Header Length: %d TTL: %d Protocol: %d '
           'Source Address: %s Destination Address: %s') %
           (ip['version'], (ip['ihl'] * 4), ip['ttl'], ip['protocol'],
            blue(ip['s_addr']), blue(ip['d_addr'])))


def print_tcp(tcp):
    print ('TCP Source Port: %s Dest Port: %s Sequence Number: %s '
           'Acknowledgement: %s TCP header length: %s Flags: (CWR: %s '
           'ECE: %s URG: %s ACK: %s PSH: %s RST: %s SYN: %s FYN: %s' %
           (tcp['source_port'], tcp['dest_port'], tcp['sequence'],
            tcp['acknowledgement'], (tcp['length']), tcp['flag_cwr'],
            tcp['flag_ece'], tcp['flag_urg'], tcp['flag_ack'], tcp['flag_psh'],
            tcp['flag_rst'], tcp['flag_syn'], tcp['flag_fyn']))


def print_openflow_header(ofp):
    version = gen.tcpip.get_ofp_version(ofp.version)
    name_version = '%s(%s)' % (version, ofp.version)
    if version == '1.0':
        name = of10.dissector.get_ofp_type(ofp.type)
        name_type = '%s(%s)' % (name, ofp.type)
    elif version == '1.3':
        name = of13.dissector.get_ofp_type(ofp.type)
        name_type = '%s(%s)' % (name, ofp.type)
    else:
        name_type = '%s' % (ofp.type)

    print ('OpenFlow Version: %s Type: %s Length: %s  XID: %s' %
           (name_version, yellow(name_type), ofp.length, red(ofp.xid)))


def print_lldp(pkt):
    lldp = pkt.of_body['print_lldp']
    print ('LLDP: Chassis Type(%s) Length: %s SubType: %s ID: %s\n'
           'LLDP: Port Type(%s) Length: %s SubType: %s ID: %s\n'
           'LLDP: TTL(%s) Length: %s Seconds: %s\n'
           'LLDP: END(%s) Length: %s' %
           (lldp['c_type'], lldp['c_length'], lldp['c_subtype'],
            green(lldp['c_id']), lldp['p_type'],
            lldp['p_length'], lldp['p_subtype'], green(lldp['p_id']),
            lldp['t_type'], lldp['t_length'], lldp['t_ttl'],
            lldp['e_type'], lldp['e_length']))
