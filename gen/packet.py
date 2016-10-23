"""
    This module defines two main classes:
        class OFMessage: used to process EACH OpenFlow message from the
            IP packet
        class Packet: used to process EACH IP packet. Each IP packet
            might have multiple OpenFlow messages (class OFMessage)
"""
import gen.filters
import of10.packet
import tcpiplib.packet
import tcpiplib.prints
from tcpiplib.tcpip import get_openflow_header
import gen.proxies
from tcpiplib.packet import IP_PROTOCOL, TCP_PROTOCOL, TCP_FLAG_PUSH
from gen.debugging import debugclass
import of13.packet


@debugclass
class OFMessage:
    """
        Used to process all data regarding this OpenFlow message
    """
    def __init__(self, pkt):
        """
            Instantiate OFMessage class
            Args:
                self: this class
                pkt: Packet class
        """
        # main_packet = full TCP/IP packet
        self.main_packet = pkt
        self.packet = pkt.this_packet
        self.offset = 0
        self.print_options = self.main_packet.print_options
        self.sanitizer = self.main_packet.sanitizer
        self.message = None
        # ofp is the real OpenFlow message
        self.ofp = None

    def process_openflow_header(self, of_header):
        """
            This method instantiate the class equivalent to the OpenFlow
                message type.
            Args:
                of_header: dictionary of the OpenFlow header

            Returns:
                0: message type unknown or OpenFlow version non-dissected
                1: No error
        """
        if of_header['version'] is 1:
            self.ofp = of10.packet.instantiate(of_header)
            if isinstance(self.ofp, (int, long)):
                print ('Debug: Packet: %s not OpenFlow\n' %
                       self.main_packet.position)
                self.offset += 8
                self.packet = self.packet[8:]
                return 0
        elif of_header['version'] is 4:
            self.ofp = of13.packet.instantiate(of_header)
            if isinstance(self.ofp, (int, long)):
                print ('Debug: Packet: %s not OpenFlow\n' %
                       self.main_packet.position)
                self.offset += 8
                self.packet = self.packet[8:]
                return 0
        else:
            return 0

        self.offset += 8
        self.packet = self.packet[8:]
        return 1

    def handle_malformed_pkts(self, exception):
        """
            In case the OpenFlow message processing crashes, this
                function tries to give some ideas of what happened
            Args:
                exception: generated expection
        """
        string = ('!!! MalFormed Packet: %s' % self.main_packet.position)
        print 'message %s\n Details about the Error:' % string
        print exception

    def process_openflow_body(self, of_header):
        """
            Process the OpenFlow content - starts with header
            Args:
                of_header: dictionary of the OpenFlow header
            Returns:
                0: Error with the OpenFlow header
                1: Success
                -1: Error processing the OpenFlow content
        """
        if not self.process_openflow_header(of_header):
            return 0
        try:
            # support for proxies
            # PacketOut will be used to collect DPID, but at this moment
            # just save DEST IP and DEST TCP port
            if of_header['type'] == 6:
                gen.proxies.insert_ip_port(self.main_packet.l3.s_addr,
                                           self.main_packet.l4.source_port)
            if of_header['type'] == 13:
                gen.proxies.insert_ip_port(self.main_packet.l3.d_addr,
                                           self.main_packet.l4.dest_port)

            self.ofp.process_msg(self.packet)
            return 1

        except Exception as exception:
            self.handle_malformed_pkts(exception)
            return -1

    def print_packet(self, pkt):
        """
            Generic printing function
            Args:
                pkt: Packet class
        """
        # Check if there is any printing filter
        if not gen.filters.filter_msg(self):
            # Only prints TCP/IP header once
            # A TCP/IP packet might contain multiple OpenFlow messages
            if pkt.printed_header is False:
                tcpiplib.prints.print_headers(pkt)
                pkt.printed_header = True
            # Print OpenFlow header - version independent
            tcpiplib.prints.print_openflow_header(self.ofp)
            # Print OpenFlow message body
            self.ofp.prints()
            print


@debugclass
class Packet:
    """
        Used to save all data about the TCP/IP packet
    """
    def __init__(self, packet, print_options, sanitizer, ctr):
        """
            Instantiate this class
            Args:
                packet: the whole captured packet from NIC or pcap file
                print_options: printing options provided by user
                sanitizer: filter file
                ctr: position of this packet in the packet capture
        """
        # Raw packet
        self.packet = packet

        # Controls
        self.position = ctr
        self.offset = 0
        self.openflow_packet = False
        self.cur_msg = 0
        self.printed_header = False
        self.this_packet = None
        self.remaining_bytes = None

        # Filters
        self.print_options = print_options
        self.sanitizer = sanitizer

        # Instantiate TCP/IP headers
        self.l1 = tcpiplib.packet.L1()
        self.l2 = tcpiplib.packet.Ethernet()
        self.l3 = tcpiplib.packet.IP()
        self.l4 = tcpiplib.packet.TCP()

        # OpenFlow messages Array
        # As multiple OpenFlow messages per packet is support
        # an array needs to be created
        self.ofmsgs = []

    def process_packet_header(self, header, time):
        """
            Process TCP/IP Header, from Layer 1 to TCP.
            Each layer has a different class. Methods parse are used
                per layer to dissect it
            Args:
                header: header of the captured packet
                time: time the packet was captured
        """
        self.l1.parse(header, time)
        self.offset = self.l2.parse(self.packet)
        if self.l2.protocol == IP_PROTOCOL:
            self.offset = self.l3.parse(self.packet, self.offset)
            if self.l3.protocol == TCP_PROTOCOL:
                self.offset = self.l4.parse(self.packet, self.offset)
                if self.l4.flag_psh == TCP_FLAG_PUSH:
                    self.openflow_packet = True
                elif self.l4.flag_fyn and self.l4.flag_ack:
                    tcpiplib.prints.print_connection_restablished(self)

    def get_remaining_bytes(self):
        return self.l1.caplen - self.offset

    def get_of_message_length(self):
        of_h = get_openflow_header(self.packet, self.offset)
        return of_h, of_h['length']

    def process_openflow_messages(self):
        self.remaining_bytes = self.get_remaining_bytes()
        while self.remaining_bytes >= 8:
            # self.this_packet is the OpenFlow message
            # let's remove the current OpenFlow message from the packet
            of_header, length = self.get_of_message_length()
            if length < 8:
                # MalFormed Packet - it could be a fragment
                return 0
            self.this_packet = self.packet[self.offset:self.offset+length]

            if len(self.this_packet) != length:
                # it means packet is smaller than it should be
                # propably MTU issue
                return 1

            # Instantiate the OpenFlow message in the ofmsgs array
            # A TCP/IP packet might contain multiple OpenFlow messages
            # Process the content, using cur_msg position of the array of msgs
            self.ofmsgs.insert(self.cur_msg, OFMessage(self))

            version = self.ofmsgs[self.cur_msg].process_openflow_body(of_header)

            if version is 0:
                return 0
            elif version is -1:
                break
            self.remaining_bytes -= length
            self.offset += length
            # If there is another OpenFlow message, instantiate another OFMsg
            if self.remaining_bytes >= 8:
                self.cur_msg += 1

        return 1

    def print_packet(self):
        """
            This method iterate over the self.ofmsgs (array of OF messages),
                printing each one of them.
        """
        for msg in self.ofmsgs:
            msg.print_packet(self)
