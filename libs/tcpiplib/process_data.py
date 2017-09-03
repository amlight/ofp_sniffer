"""
    This module has functions to help processing the data from
    PacketIn and PacketOut.
"""


from pyof.foundation.basic_types import BinaryData
from libs.tcpiplib.packet import Ethernet, VLAN, IP, TCP, LLDP, ARP, OessFvd


def dissect_data(data, start=0):
    """
        This function aims to dissect PacketIn and PacketOut data
        It assumes it is
            Ethernet [vlan] (BDDP|LLDP|ARP|IP) [TCP|UDP]
    Args:
        data: BinaryData
        start: offset
    Returns:
        payload: array with all classes
    """
    packet = data.value
    payload = []
    # Ethernet
    eth = Ethernet()
    eth.parse(packet[start:start + 14], 1)
    payload.append(eth)

    # VLAN or not - ETYPE 0x8100 or 33024
    etype = '0x0000'

    start += 14
    if eth.protocol in [33024]:
        # Frame has VLAN

        vlan = VLAN()
        vlan.parse(packet[start:start + 4])
        payload.append(vlan)
        etype = vlan.protocol
        start += 4
    else:
        etype = eth.protocol

    # if there is no content, return
    if len(packet[start:]) == 0:
        return payload

    # OESS FVD
    if etype in [34998]:
        fvd = OessFvd()
        try:
            fvd.parse(packet[start:])
        except Exception as error:
            print(error)
        payload.append(fvd)
        return payload

    # LLDP - ETYPE 0x88CC or 35020 or
    # BBDP - ETYPE 0x8942 or 35138
    if etype in [35020, 35138]:
        lldp = LLDP()
        try:
            lldp.parse(packet[start:])
        except:
            pass
        if not isinstance(lldp, LLDP):
            lldp.c_id = 0
        else:
            payload.append(lldp)
        return payload

    # IP - ETYPE 0x800 or 2048
    if etype in [2048]:
        ip_addr = IP()
        ip_addr.parse(packet, start)
        payload.append(ip_addr)
        if ip_addr.protocol is 6:
            tcp = TCP()
            tcp.parse(packet, start + ip_addr.length)
            payload.append(tcp)
        return payload

    # ARP - ETYPE 0x806 or 2054
    if etype in [2054]:
        arp = ARP()
        arp.parse(packet[start:])
        payload.append(arp)
        return payload

    return payload


def is_protocol(data, lldp=False, oess=False, arp=False):
    """
        Check if Data is protocol provided
        Args:
            data: PacketOut/PacketIn/OESS data
            lldp: check for lldp
            oess: check for oess
            arp: check for arp
        Returns:
            protocol class if True
            False if it is not
    """
    protocol = []
    return_protocol = False
    if lldp:
        protocol.append(35020)  # LLDP
        protocol.append(35138)  # BDDP
    elif oess:
        protocol.append(34998)  # Private
    elif arp:
        protocol.append(2054)  # ARP 0x806
    else:
        return_protocol = True

    if isinstance(data, BinaryData):
        data = dissect_data(data)

    try:
        eth = data.pop(0)
        next_protocol = eth.protocol

        if next_protocol in [33024]:
            vlan = data.pop(0)
            if return_protocol:
                return vlan.protocol

            next_protocol = vlan.protocol

        if next_protocol in protocol:
            return True

        return False

    except Exception as error:
        print(error)
        return False


def get_protocol(data, lldp=False, oess=False, arp=False):
    """
        Get protocol from data
        Args:
            data: PacketOut/PacketIn/OESS data
            lldp: check for lldp
            oess: check for oess
            arp: check for arp
        Returns:
            protocol class if True
            False if it is not
    """
    protocol = []
    if lldp:
        protocol.append(35020)  # LLDP
        protocol.append(35138)  # BDDP
    elif oess:
        protocol.append(34998)  # Private
    elif arp:
        protocol.append(2054)  # ARP 0x806
    else:
        return False

    if isinstance(data, BinaryData):
        data = dissect_data(data)

    try:
        eth = data.pop(0)
        next_protocol = eth.protocol

        if next_protocol in [33024]:
            vlan = data.pop(0)
            next_protocol = vlan.protocol

        if next_protocol in protocol:
            return data.pop(0)

        return False

    except Exception as error:
        print(error)
        return False
