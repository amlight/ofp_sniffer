from struct import unpack
import socket


def get_ethernet_frame(packet):
    '''
        Returns src_mac, dst_mac and protocol from packet
    '''
    # Ethernet Header has 14 bytes
    eth_length = 14
    eth_header = packet[:eth_length]
    dst_mac, src_mac, prot = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(prot)
    return src_mac, dst_mac, eth_protocol, eth_length


def get_ip_packet(packet, eth_length):
    '''
        Returns IP Header fields
    '''
    ip_min_len = 20
    ip_header = packet[eth_length:ip_min_len+eth_length]
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    return version, ihl, iph_length, ttl, protocol, s_addr, d_addr


def get_tcp_stream(packet, header_size):
    '''
        Returns TCP Header fields
    '''
    tcp_length = 20
    tcp_header = packet[header_size:header_size+tcp_length]
    tcph = unpack('!HHLLBBHHH', tcp_header)
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    tcph_length = tcph_length * 4
    flags = tcph[5]  # Ignoring Flag NS
    flag_cwr = flags & 0x80
    flag_ece = flags & 0x40
    flag_urg = flags & 0x20
    flag_ack = flags & 0x10
    flag_psh = flags & 0x08
    flag_rst = flags & 0x04
    flag_syn = flags & 0x02
    flag_fyn = flags & 0x01
    return source_port, dest_port, sequence, acknowledgement, tcph_length, \
        flag_cwr, flag_ece, flag_urg, flag_ack, flag_psh, flag_rst, \
        flag_syn, flag_fyn


def get_udp_datagram():
    return


def get_openflow_header(packet, start):
    '''
        Returns OpenFlow header
        It is non-version aware
    '''
    of_header_length = 8
    of_header = packet[start:of_header_length+start]
    try:
        ofh = unpack('!BBHL', of_header)
        of_version = ofh[0]
        of_type = ofh[1]
        of_length = ofh[2]
        of_xid = ofh[3]
        return of_version, of_type, of_length, of_xid

    except Exception as exception:
        print (exception)
        return -1


def get_lldp():
    return
