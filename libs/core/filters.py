"""
    Filters to be used
    Any customized print filters should be inserted in this file
    Filters are provided via CLI option -F json-file
"""


from libs.core.printing import PrintingOptions
from libs.core.sanitizer import Sanitizer
from libs.tcpiplib.tcpip import get_ofp_version
from libs.tcpiplib.process_data import is_protocol
from libs.tcpiplib.process_data import get_protocol
from libs.gen.dpid_handling import clear_dpid


def filter_msg(msg):
    """
        This method will be the core of all filters. Any new filter comes here
    Args:
        msg: OFMessage class
    Returns:
        False: Don't filter packet
        True: Filter it (don't print)
    """

    if PrintingOptions().is_quiet():
        # Don't print anything. Used in conjunction with some apps.
        return True

    if not PrintingOptions().has_filters():
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

    # Don't filter
    return False


def filter_of_version(msg):
    """
        Check if the OpenFlow version is allowed
        Args:
            msg: OFMessage class
        Returns:
            False: Don't filter packet
            True: Filter it (don't print)
    """
    name_version = get_ofp_version(msg.ofp.header.version.value)
    supported_versions = []
    try:
        for version in Sanitizer().allowed_of_versions:
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
            False: Don't filter packet
            True: Filter it (don't print)
    """
    name_version = get_ofp_version(msg.ofp.header.version.value)
    # OF Types to be ignored through json file (-F)
    try:
        rejected_types = Sanitizer().allowed_of_versions[name_version]
        if msg.ofp.header.message_type in rejected_types['rejected_of_types']:
            return True
    except KeyError:
        pass
    return False


def ethertype_filters(msg):
    """
        Filter PacketIn and PacketOut messages based on Ethertype
        Sanitizer filter (-F), entry "filters", "ethertype"
        Args:
            msg: class OFMessage
        Returns:
            False: Don't filter packet
            True: Filter it (don't print)
    """
    if msg.ofp.header.message_type in [10, 13]:
        try:
            filters = Sanitizer().filters['ethertypes']
        except KeyError:
            return False

        if not len(filters):
            # No filters
            return False

        # Go to payload
        try:
            if is_protocol(msg.ofp.data, lldp=True) and filters['lldp']:
                return True
            if is_protocol(msg.ofp.data, oess=True) and filters['fvd']:
                return True
            if is_protocol(msg.ofp.data, arp=True) and filters['arp']:
                return True
        except KeyError:
            pass

        # Other Ethertypes listed as hex
        for protocol in filters['others']:
            try:
                if is_protocol(msg.ofp.data) == int(protocol, 16):
                    return True
            except ValueError:
                pass

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
    if msg.ofp.header.message_type not in [10, 13]:
        return False

    # It has to be a LLDP packet
    if not is_protocol(msg.ofp.data, lldp=True):
        return False

    try:
        # If it is a PacketIn ...
        if msg.ofp.header.message_type in [10]:
            # It has to have a packetIn_filter filter
            filters = Sanitizer().filters['packetIn_filter']
            filter_port = filters['in_port']

        # If it a PacketOut...
        else:
            # It has to have a packetOut_filter filter
            filters = Sanitizer().filters['packetOut_filter']
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
    lldp_msg = get_protocol(msg.ofp.data, lldp=True)
    switch_dpid = clear_dpid(filter_dpid)

    if print_switch_dpid(switch_dpid, lldp_msg.c_id):
        if msg.ofp.header.message_type in [10]:
            if print_port(filter_port, str(msg.ofp.in_port)):
                print_it = True
        else:
            if print_port(filter_port, str(lldp_msg.p_id)):
                print_it = True

    if print_it:
        return False

    return True


def print_switch_dpid(filter_dpid, packet_dpid):
    """
        Confirm if filter_dpid is packet_dpid or any
    """
    packet_dpid = clear_dpid(packet_dpid)
    if filter_dpid in [packet_dpid, 'Any', 'any', 'ANY']:
        return True
    return False


def print_port(filter_port, packet_port):
    """
        Confirm if filter_port is packet_port or any
    """
    if filter_port in [packet_port, 'Any', 'any', 'ANY']:
        return True
    return False
