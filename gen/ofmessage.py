"""

"""
import gen.proxies
import libs.filters
import of10.packet
import of13.packet
import tcpiplib.packet
import tcpiplib.prints
from libs.debugging import debugclass


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
        # self.print_options = self.main_packet.print_options
        # self.sanitizer = self.main_packet.sanitizer
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
            if isinstance(self.ofp, int):
                print('Debug: Packet: %s not OpenFlow\n' %
                      self.main_packet.position)
                self.offset += 8
                self.packet = self.packet[8:]
                return 0
        elif of_header['version'] is 4:
            self.ofp = of13.packet.instantiate(of_header)
            if isinstance(self.ofp, int):
                print('Debug: Packet: %s not OpenFlow\n' %
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
        print('message %s\n Details about the Error:' % string)
        print(exception)

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
        if not libs.filters.filter_msg(self):
            # Only prints TCP/IP header once
            # A TCP/IP packet might contain multiple OpenFlow messages
            if pkt.printed_header is False:
                tcpiplib.prints.print_headers(pkt)
                pkt.printed_header = True
            # Print OpenFlow header - version independent
            tcpiplib.prints.print_openflow_header(self.ofp)
            # Print OpenFlow message body
            self.ofp.prints()
            print()
