"""
    Module to define classes in use by the TCP/IP stack
"""

from struct import unpack
import socket


IP_PROTOCOL = 8
TCP_PROTOCOL = 6
TCP_FLAG_PUSH = 8
OF_HEADER_SIZE = 8


class L1:
    """
        Class to dissect L1 fields
    """
    def __init__(self):
        self.caplen = None
        self.truncate = None
        self.time = None

    def parse(self, header, time):
        self.caplen = header.getlen()
        self.truncate = header.getcaplen()
        self.time = time


class Ethernet:
    """
        Class to dissect Ethernet fields
    """
    def __init__(self):
        self.src_mac = None
        self.dst_mac = None
        self.protocol = None
        self.length = 14  # Ethernet header has 14 bytes

    def parse(self, packet, host_order=0):
        eth_raw = packet[:self.length]
        ethernet = unpack('!6s6sH', eth_raw)
        self.dst_mac = ethernet[0]
        self.src_mac = ethernet[1]

        # When Ethernet is captured directly from the wire,
        # use host_order big-endian. When the frame is encapsulated
        # inside an OpenFlow PacketIn or Out, it is little-endian
        if not host_order:
            self.protocol = socket.ntohs(ethernet[2])
        else:
            self.protocol = ethernet[2]
        return self.length


class IP:
    """
        Class to dissect IP fields
    """
    def __init__(self):
        self.version = None
        self.ihl = None
        self.length = 20  # Minimum length
        self.ttl = None
        self.protocol = None
        self.s_addr = None
        self.d_addr = None

    def parse(self, packet, offset):
        ip_raw = packet[offset:self.length + offset]
        iph = unpack('!BBHHHBBH4s4s', ip_raw)
        version_ihl = iph[0]
        self.version = version_ihl >> 4
        self.ihl = version_ihl & 0xF
        self.length = self.ihl * 4
        self.ttl = iph[5]
        self.protocol = iph[6]
        self.s_addr = socket.inet_ntoa(iph[8])
        self.d_addr = socket.inet_ntoa(iph[9])
        return self.length + offset


class TCP:
    """
        Class to dissect TCP fields
    """
    def __init__(self):
        self.source_port = None
        self.dest_port = None
        self.sequence = None
        self.acknowledgement = None
        self.length = 20  # minimun length.
        self.flag_cwr = None
        self.flag_ece = None
        self.flag_urg = None
        self.flag_ack = None
        self.flag_psh = None
        self.flag_rst = None
        self.flag_syn = None
        self.flag_fyn = None

    def parse(self, packet, offset):
        tcp_raw = packet[offset:offset + self.length]
        tcph = unpack('!HHLLBBHHH', tcp_raw)
        self.source_port = tcph[0]
        self.dest_port = tcph[1]
        self.sequence = tcph[2]
        self.acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        self.length = tcph_length * 4
        flags = tcph[5]
        self.flag_cwr = flags & 0x80
        self.flag_ece = flags & 0x40
        self.flag_urg = flags & 0x20
        self.flag_ack = flags & 0x10
        self.flag_psh = flags & 0x08
        self.flag_rst = flags & 0x04
        self.flag_syn = flags & 0x02
        self.flag_fyn = flags & 0x01
        return self.length + offset


class VLAN:
    """
        Class to dissect VLAN fields
    """
    def __init__(self):
        self.vid = None
        self.cfi = None
        self.pcp = None
        self.protocol = None
        self.ethertype = None

    def parse(self, packet):
        vlan_length = 2
        ethertype = 2
        vlan_raw = packet[:vlan_length + ethertype]
        vlan_p = unpack('!HH', vlan_raw)
        self.pcp = vlan_p[0] >> 13
        self.cfi = (vlan_p[0] & 0x1000) >> 12
        self.vid = vlan_p[0] & 0xfff
        self.protocol = vlan_p[1]
        self.ethertype = self.protocol


class LLDP:
    """
        Class to dissect LLDP fields
        This is not a full LLDP dissection, just basic fields
        The idea is to get the DPID and ports
    """
    def __init__(self):
        self.c_type = None
        self.c_length = None
        self.c_subtype = None
        self.c_id = None
        self.p_type = None
        self.p_length = None
        self.p_subtype = None
        self.p_id = None
        self.t_type = None
        self.t_length = None
        self.t_ttl = None
        self.e_type = None
        self.e_length = None

    def parse(self, packet):
        # Chassis
        # TLV (1) + Length = 2 bytes | Sub-type = 1 Byte
        chassis_raw = packet[:3]
        chassis = unpack('!HB', chassis_raw)
        self.c_type = chassis[0] >> 9
        if self.c_type is not 1:
            return {}
        self.c_length = chassis[0] & 0xFF
        self.c_subtype = chassis[1]
        length = self.c_length - 1
        # Get C_ID
        chassis_raw = packet[3:3 + length]
        string = '!%ss' % length
        chassis = unpack(string, chassis_raw)
        self.c_id = chassis[0]

        start = 3 + length

        # Port
        # TLV (2) + Length = 2 Bytes | Port_id = 1 Byte
        port_raw = packet[start:start + 3]
        port = unpack('!HB', port_raw)
        self.p_type = port[0] >> 9
        if self.p_type is not 2:
            return {}
        self.p_length = port[0] & 0xFF
        self.p_subtype = port[1]
        length = self.p_length - 1
        # Get P_ID
        port_raw = packet[start + 3:start + 3 + length]
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
        self.p_id = port[0]

        start = start + 3 + length

        # TTL
        ttl_raw = packet[start:start + 4]
        ttl = unpack('!HH', ttl_raw)
        self.t_type = ttl[0] >> 9
        if self.t_type is not 3:
            return {}
        self.t_length = ttl[0] & 0xFF
        self.t_ttl = ttl[1]

        start += 4

        # Loop to get User-Specific TLVs
        while len(packet[start:]) > 2:
            next_raw = packet[start:start + 2]
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
                subtype_raw = packet[start + 5:start + 6]
                subtype = unpack('!B', subtype_raw)
                if subtype[0] == 2:
                    content_raw = packet[start + 6:start + 6 + length]
                    string = '!%ss' % length
                    content = unpack(string, content_raw)
                    self.c_id = content[0]

            start = start + n_length + 2

        # END
        end_raw = packet[start:start + 2]
        end = unpack('!H', end_raw)
        self.e_type = end[0] >> 9
        self.e_length = end[0] & 0xFF


class ARP:
    """
        Class to dissect ARP fields
    """
    def __init__(self):
        self.hw_type = None
        self.prot_type = None
        self.hw_len = None
        self.prot_len = None
        self.opcode = None
        self.src_mac = None
        self.src_ip = None
        self.dst_mac = None
        self.dst_ip = None

    def parse(self, packet):
        arp_raw = packet[:28]
        arp = unpack('!HHBBH6sL6sL', arp_raw)
        self.hw_type = arp[0]
        self.prot_type = arp[1]
        self.hw_len = arp[2]
        self.prot_len = arp[3]
        self.opcode = arp[4]
        self.src_mac = arp[5]
        self.src_ip = arp[6]
        self.dst_mac = arp[7]
        self.dst_ip = arp[8]
