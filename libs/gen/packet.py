"""
    Class Packet: used to process EACH IP packet. Each IP packet
        might have multiple OpenFlow messages (class OFMessage)
"""
from libs.tcpiplib.packet import IP_PROTOCOL, TCP_PROTOCOL, TCP_FLAG_PUSH
from libs.gen.ofmessage import OFMessage
from libs.tcpiplib.tcpip import get_openflow_header
from libs.debugging import debugclass
import libs.tcpiplib.packet
import libs.tcpiplib.prints
import libs.gen.proxies


@debugclass
class Packet:
    """
        Used to save all data about the TCP/IP packet
    """
    def __init__(self, packet, ctr, header):
        """
            Instantiate this class
            Args:
                packet: the whole captured packet from NIC or pcap file
                ctr: position of this packet in the packet capture
        """
        # Raw packet
        self.packet = packet

        # Controls
        self.position = ctr
        self.offset = 0
        self.is_openflow_packet = False
        self.cur_msg = 0
        self.printed_header = False
        self.this_packet = None
        self.remaining_bytes = None

        # Instantiate TCP/IP headers
        self.l1 = libs.tcpiplib.packet.L1()
        self.l2 = libs.tcpiplib.packet.Ethernet()
        self.l3 = libs.tcpiplib.packet.IP()
        self.l4 = libs.tcpiplib.packet.TCP()

        # OpenFlow messages Array
        # As multiple OpenFlow messages per packet is possible
        # an list of messages needs to be created
        self.ofmsgs = []

        # Process packet
        self.process_packet_header(header)


    def process_packet_header(self, header):
        """
            Process TCP/IP Header, from Layer 1 to TCP.
            Each layer has a different class. Methods parse are used
                per layer to dissect it
            Args:
                header: header of the captured packet
                time: time the packet was captured
        """
        self.l1.parse(header)
        self.offset = self.l2.parse(self.packet)
        if self.l2.protocol == IP_PROTOCOL:
            self.offset = self.l3.parse(self.packet, self.offset)
            if self.l3.protocol == TCP_PROTOCOL:
                self.offset = self.l4.parse(self.packet, self.offset)
                if self.l4.flag_psh == TCP_FLAG_PUSH:
                    self.is_openflow_packet = True
                elif self.l4.flag_fyn and self.l4.flag_ack:
                    libs.tcpiplib.prints.print_connection_restablished(self)

    def process_openflow_messages(self):
        """

        """
        self.remaining_bytes = self.get_remaining_bytes()

        while self.remaining_bytes >= 8:
            # self.this_packet is the OpenFlow message
            # let's get the current OpenFlow message from the packet
            of_header, length = self.get_of_message_length()
            if length < 8:
                # MalFormed Packet - it could be a fragment
                return False

            self.this_packet = self.packet[self.offset:self.offset+length]
            if len(self.this_packet) != length:
                # it means packet is smaller than it should be
                # propably MTU issue
                return False

            version = self.add_of_msg_to_list(of_header, self.this_packet)

            if version is 0:
                return False
            elif version is -1:
                break

            self.remaining_bytes -= length
            self.offset += length

            # If there are other OpenFlow messages, let's continue
            if self.remaining_bytes >= 8:
                self.cur_msg += 1

        return True

    def add_of_msg_to_list(self, of_header, this_packet):
        """
            Instantiate the OpenFlow message in the ofmsgs array
            A TCP/IP packet might contain multiple OpenFlow messages
            Process the content, using cur_msg position of the array of msgs
        """
        self.ofmsgs.insert(self.cur_msg, OFMessage(this_packet, self.position))
        # Time to convert from Binary to OpenFlow!!
        result = self.ofmsgs[self.cur_msg].process_openflow_body(of_header)
        if result == 1:
            # Extra Feature
            self.proxy_support(self.ofmsgs[self.cur_msg].ofp)
        else:
            return result

    def print_packet(self):
        """
            This method iterate over the self.ofmsgs (array of OF messages),
                printing each one of them.
        """
        for msg in self.ofmsgs:
            msg.print_packet(self)

    def get_remaining_bytes(self):
        """

        """
        return self.l1.caplen - self.offset

    def get_of_message_length(self):
        """

        """
        of_h = get_openflow_header(self.packet, self.offset)
        return of_h, of_h['length']

    def proxy_support(self, msg):
        """
            Support for proxies
            PacketOut will be used to collect DPID, but at this moment
            just save DEST IP and DEST TCP port
        """
        if msg.type == 6:
            libs.gen.proxies.insert_ip_port(self.l3.s_addr,
                                            self.l4.source_port)
        elif msg.type == 13:
            libs.gen.proxies.insert_ip_port(self.l3.d_addr,
                                            self.l4.dest_port)
