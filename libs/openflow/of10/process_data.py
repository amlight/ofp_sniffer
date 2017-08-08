"""

"""
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
        """
            Frame has VLAN
        """
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
        ip = IP()
        ip.parse(packet, start)
        payload.append(ip)
        if ip.protocol is 6:
            tcp = TCP()
            tcp.parse(packet, start + ip.length)
            payload.append(tcp)
        return payload

    # ARP - ETYPE 0x806 or 2054
    if etype in [2054]:
        arp = ARP()
        arp.parse(packet[start:])
        payload.append(arp)
        return payload

    return payload
