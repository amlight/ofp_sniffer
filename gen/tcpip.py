from struct import unpack
import socket


def get_ethernet_frame(packet, host_order=0):
    # Ethernet Header has 14 bytes
    eth_length = 14
    eth_header = packet[:eth_length]
    dst_mac, src_mac, prot = unpack('!6s6sH', eth_header)
    if not host_order:
        eth_protocol = socket.ntohs(prot)
    else:
        eth_protocol = prot
    eth_frame = {'src_mac': src_mac, 'dst_mac': dst_mac,
                 'protocol': eth_protocol, 'length': eth_length}
    return eth_frame


def get_ethertype(etype):
    etypes = {8: 'IP',
              2048: 'IP',
              2054: 'ARP',
              33024: 'VLAN',
              34925: 'IPv6',
              34887: 'MPLS',
              35020: 'LLDP',
              35138: 'BBDP',
              34998: 'PRIVATE'}
    try:
        return '%s(%s)' % (etypes[etype], hex(etype))
    except:
        return hex(etype)


def get_ethernet_vlan(packet):
    vlan_length = 2
    vlan_pq = packet[:vlan_length]
    vlan_p = unpack('!H', vlan_pq)
    prio = vlan_p[0] >> 13
    cfi = (vlan_p[0] & 0x1000) >> 12
    vid = vlan_p[0] & 0xfff
    vlan = {'prio': prio, 'cfi': cfi, 'vid': vid}
    return vlan


def get_next_etype(packet):
    etype_length = 2
    et = packet[:etype_length]
    return unpack('!H', et)[0]


def get_arp(packet):
    arp_raw = packet[:28]
    arp = unpack('!HHBBH6sL6sL', arp_raw)
    arp_frame = {'hw_type': arp[0], 'prot_type': arp[1], 'hw_len': arp[2],
                 'prot_len': arp[3], 'opcode': arp[4], 'src_mac': arp[5],
                 'src_ip': arp[6], 'dst_mac': arp[7], 'dst_ip': arp[8]}
    return arp_frame


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


def get_ofp_version(version):
    of_versions = {0: 'Experimental',
                   1: '1.0',
                   2: '1.1',
                   3: '1.2',
                   4: '1.3',
                   5: '1.4',
                   6: '1.5'}
    try:
        return of_versions[version]
    except:
        return 'Unknown(%s)' % version


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


def get_lldp(packet):
    # Chassis
    # TLV (1) + Length = 2 bytes | Sub-type = 1 Byte
    chassis_raw = packet[:3]
    chassis = unpack('!HB', chassis_raw)
    c_type = chassis[0] >> 9
    if c_type is not 1:
        return {}
    c_length = chassis[0] & 0xFF
    c_subtype = chassis[1]
    length = c_length - 1
    # Get C_ID
    chassis_raw = packet[3:3+length]
    string = '!%ss' % length
    chassis = unpack(string, chassis_raw)
    c_id = chassis[0]

    start = 3 + length

    # Port
    # TLV (2) + Length = 2 Bytes | Port_id = 1 Byte
    port_raw = packet[start:start+3]
    port = unpack('!HB', port_raw)
    p_type = port[0] >> 9
    if p_type is not 2:
        return {}
    p_length = port[0] & 0xFF
    p_subtype = port[1]
    length = p_length - 1
    # Get P_ID
    port_raw = packet[start+3:start+3+length]
    # string = '!%ss' % length
    if length is 1:
        string = '!B'
    elif length is 2:
        string = '!H'
    elif length is 4:
        string = '!L'
    else:
        string = '!%ss' % length
    port = unpack(string, port_raw)
    p_id = port[0]
    start = start + 3 + length

    # TTL
    ttl_raw = packet[start:start+4]
    ttl = unpack('!HH', ttl_raw)
    t_type = ttl[0] >> 9
    if t_type is not 3:
        return {}
    t_length = ttl[0] & 0xFF
    t_ttl = ttl[1]

    start = start + 4
    # Loop to get User-Specific TLVs
    while len(packet[start:]) > 2:
        next_raw = packet[start:start+2]
        nraw = unpack('!H', next_raw)
        n_type = nraw[0] >> 9
        n_length = nraw[0] & 0xFF
        length = n_length - 4

        if n_type == 0:
            break
        elif n_type == 127:
            # We only want TLV 127, OUI a42305 (ONOS)
            # Then we will look for Subtype 2 and get the content
            # Skip the OUI - 3 bytes
            subtype_raw = packet[start+5:start+6]
            subtype = unpack('!B', subtype_raw)
            start = start + 6
            if subtype[0] == 2:
                content_raw = packet[start:start+length]
                string = '!%ss' % length
                content = unpack(string, content_raw)
                c_id = content[0]

        start = start + n_length + 2

    # END
    end_raw = packet[start:start+2]
    end = unpack('!H', end_raw)
    e_type = end[0] >> 9
    e_length = end[0] & 0xFF

    lldp = {'c_type': c_type, 'c_length': c_length, 'c_subtype': c_subtype,
            'c_id': c_id, 'p_type': p_type, 'p_length': p_length,
            'p_subtype': p_subtype, 'p_id': p_id, 't_type': t_type,
            't_length': t_length, 't_ttl': t_ttl, 'e_type': e_type,
            'e_length': e_length}

    return lldp
