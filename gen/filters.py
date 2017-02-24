"""
    Filters to be used
    Any customized print filters should be inserted in this file
    Filters are provided via CLI option -F json-file
"""


import tcpiplib.tcpip
import tcpiplib.packet
import of10


def filter_msg(msg):
    """
        This method will be the core of all filters. Any new filter comes here
    Args:
        msg: OFMessage class
    Returns:
        False: Don' filter packet
        True: Filter it (don't print)
    """
    if msg.print_options['filters'] is 0:
        # User hasn't selected CLI option -F
        return False

    # Filter per OF Version
    if filter_of_version(msg):
        return True

    # Filter per OF Message Type
    if filter_of_type(msg):
        return True

    # Filter Ethertypes from PacketIn/Out messages
    if ethertype_filters(msg):
        return True

    # Filter PacketIn/Out based on DPID and Port
    if dpid_filters(msg):
        return True

    return False


def filter_of_version(msg):
    """
        Check if the OpenFlow version is allowed
        Args:
            msg: OFMessage class
        Returns:
            False: Don' filter packet
            True: Filter it (don't print)
    """
    name_version = tcpiplib.tcpip.get_ofp_version(msg.ofp.version)
    supported_versions = []
    try:
        for version in msg.sanitizer['allowed_of_versions']:
            supported_versions.append(version)
        if name_version not in supported_versions:
            return True
    except KeyError:
        pass
    return False


def filter_of_type(msg):
    """
        Filter per OF Message Type
        Args:
            msg: OFMessage class
        Returns:
            False: Don' filter packet
            True: Filter it (don't print)
    """
    name_version = tcpiplib.tcpip.get_ofp_version(msg.ofp.version)
    # OF Types to be ignored through json file (-F)
    try:
        rejected_types = msg.sanitizer['allowed_of_versions'][name_version]
        if msg.ofp.type in rejected_types['rejected_of_types']:
            return True
    except KeyError:
        pass
    return False


def ethertype_filters(msg):
    """
        Filter PacketIn and PacketOut messages with LLDP or BDDP
        Sanitizer filter (-F), entry "filters", "ethertype"
        Args:
            msg: class OFMessage
        Returns:
            False: Don' filter packet
            True: Filter it (don't print)
    """
    if msg.ofp.type in [10, 13]:
        try:
            filters = msg.sanitizer['filters']['ethertypes']
        except KeyError:
            return False
        if not len(filters):
            # No filters
            return False
        # Go to payload
        idx = 0
        if isinstance(msg.ofp.data[idx], tcpiplib.packet.Ethernet):
            next_protocol = msg.ofp.data[idx].protocol
            idx += 1
            if isinstance(msg.ofp.data[idx], tcpiplib.packet.VLAN):
                next_protocol = msg.ofp.data[idx].protocol
            try:
                if next_protocol in [35020, 35138] and filters['lldp']:
                    return True
                if next_protocol in [34998] and filters['fvd']:
                    return True
                if next_protocol in [2054] and filters['arp']:
                    return True
            except KeyError:
                # If there is no entry 'lldp' for example, Python will complain.
                # So, just ignore because user does not want to filter lldp.
                pass

            # Other Ethertypes listed as hex
            for protocol in filters['others']:
                if next_protocol == int(protocol, 16):
                    return True

    return False


def dpid_filters(msg):
    """
        Filter PacketIn and PacketOut messages based on DPID and ports
        Sanitizer filter (-F), entry "filters", "packetIn_filter" or
          "packetOut_filter"
          If switch_dpid AND in_port are Any, don't filter (print it)
          If switch_dpid OR in_port are NOT Any, print only what matches the
            most specific (filter everything else)
        Args:
            msg: class OFMessage
        Returns:
            False: Don' filter packet (print it)
            True: Filter it (don't print)
    """

    # It has to be a PacketOut or PacketIn
    if msg.ofp.type not in [10, 13]:
        return False

    # It has to be a LLDP packet
    idx = 0
    if isinstance(msg.ofp.data[idx], tcpiplib.packet.Ethernet):
        next_protocol = msg.ofp.data[idx].protocol
        idx += 1
        if isinstance(msg.ofp.data[idx], tcpiplib.packet.VLAN):
            next_protocol = msg.ofp.data[idx].protocol
        try:
            if next_protocol not in [35020, 35138]:
                return False
        except KeyError:
            return False

    try:
        # If it is a PacketIn ...
        if msg.ofp.type in [10]:
            # It has to have a packetIn_filter filter
            filters = msg.sanitizer['filters']['packetIn_filter']
            filter_port = filters['in_port']
        # If it a PacketOut...
        else:
            # It has to have a packetOut_filter filter
            filters = msg.sanitizer['filters']['packetOut_filter']
            filter_port = filters['out_port']

        filter_dpid = filters['switch_dpid']

    except KeyError:
        return False
    if not len(filters):
        return False

    # Was switch_dpid or in_port specified by user?
    if filter_dpid in ['any', 'Any', 'ANY']:
        if filter_port in ['any', 'Any', 'ANY']:
            return False

    # If we got here, it means we have content to avoid printing
    print_it = False
    lldp_msg = msg.ofp.data[idx+1]
    try:
        switch_dpid = filter_dpid.split(':')[1]
    except:
        switch_dpid = filter_dpid

    if print_switch_dpid(switch_dpid, lldp_msg.c_id):
        if msg.ofp.type in [10]:
            if print_port(filter_port, str(msg.ofp.in_port)):
                print_it = True
        else:
            if print_port(filter_port, str(lldp_msg.p_id)):
                print_it = True

    if print_it:
        return False
    else:
        return True


def print_switch_dpid(filter_dpid, packet_dpid):
    try:
        p_dpid = packet_dpid.split(':')[1]
    except:
        p_dpid = packet_dpid
    if filter_dpid in [p_dpid, 'Any', 'any', 'ANY']:
        return True
    return False


def print_port(filter_port, packet_port):
    if filter_port in [packet_port, 'Any', 'any', 'ANY']:
        return True
    return False