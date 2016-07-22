from struct import unpack


def get_ethertype(etype):
    """
        Converts Ethertype from number to name
        Args:
            etype: etype number collected
        Returns:
            etype name
    """
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
    except KeyError:
        return hex(etype)


def get_ofp_version(version):
    """
        Converts OpenFlow version number to a human version
        Args:
            version: integer version of the OpenFlow version
        Returns:
            human version of the OpenFlow version
    """
    of_versions = {0: 'Experimental',
                   1: '1.0',
                   2: '1.1',
                   3: '1.2',
                   4: '1.3',
                   5: '1.4',
                   6: '1.5'}
    try:
        return of_versions[version]
    except KeyError:
        return 'Unknown(%s)' % version


def get_openflow_header(packet, start):
    """
        Returns OpenFlow header
        It is not a version aware
        Args:
            packet: packet content
            start: offset
    """
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
