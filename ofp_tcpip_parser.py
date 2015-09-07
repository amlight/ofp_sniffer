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
    eth_frame = {'src_mac': src_mac, 'dst_mac': dst_mac,
                 'protocol': eth_protocol, 'length': eth_length}
    return eth_frame


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
    ip_pkt = {'version': version, 'ihl': ihl, 'length': iph_length,
              'ttl': ttl, 'protocol': protocol, 's_addr': s_addr,
              'd_addr': d_addr}
    return ip_pkt


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
    tcp_stream = {'source_port': source_port, 'dest_port': dest_port,
                  'sequence': sequence, 'acknowledgement': acknowledgement,
                  'length': tcph_length, 'flag_cwr': flag_cwr,
                  'flag_ece': flag_ece, 'flag_urg': flag_urg,
                  'flag_ack': flag_ack, 'flag_psh': flag_psh,
                  'flag_rst': flag_rst, 'flag_syn': flag_syn,
                  'flag_fyn': flag_fyn}
    return tcp_stream


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
        of_header = {'version': of_version, 'type': of_type,
                     'length': of_length, 'xid': of_xid}
        return of_header

    except Exception as exception:
        print exception
        of_header['version'] = -1
        return of_header


def get_lldp():
    return
