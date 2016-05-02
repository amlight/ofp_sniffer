'''
    Filters to be used
'''
import tcpiplib.tcpip


def filter_msg(msg):
    """
        This method will be the core of all filters. Any new filter comes here
    Args:
        msg: class OFMessage
    Returns:
        False: Don' filter packet
        True: Filter it (don't print)
    """
    if msg.print_options['filters'] is 0:
        # User hasn't selected -F
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

    return False


def filter_of_version(msg):
    # Check if the OpenFlow version is allowed
    name_version = tcpiplib.tcpip.get_ofp_version(msg.ofp.version)
    supported_versions = []
    for version in msg.sanitizer['allowed_of_versions']:
        supported_versions.append(version)
    if name_version not in supported_versions:
        return True
    return False


def filter_of_type(msg):
    name_version = tcpiplib.tcpip.get_ofp_version(msg.ofp.version)
    # OF Types to be ignored through json file (-F)
    rejected_types = msg.sanitizer['allowed_of_versions'][name_version]
    if msg.ofp.type in rejected_types['rejected_of_types']:
        return True
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
        filters = msg.sanitizer['filters']['ethertypes']
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
                pass

            # Other Ethertypes listed as hex
            for protocol in filters['others']:
                if next_protocol == int(protocol, 16):
                    return True

    return False
