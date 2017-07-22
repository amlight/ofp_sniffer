"""

"""

import libs.filters
import libs.gen.proxies
import libs.tcpiplib.packet
import libs.tcpiplib.prints
import libs.openflow.instantiate
from libs.debugging import debugclass


@debugclass
class OFMessage:
    """
        Used to process all data regarding this OpenFlow message
    """
    def __init__(self, this_packet, position):
        """
            Instantiate OFMessage class
            Args:
                self: this class
                this_packet: OpenFlow msg
                position: packet number
        """
        self.position = position
        self.packet = this_packet
        self.offset = 0
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
        self.ofp = libs.openflow.instantiate.instantiate_msg(of_header)
        if isinstance(self.ofp, int):
            print('Debug: Packet: %s not OpenFlow\n' % self.position)
            self.offset += 8
            self.packet = self.packet[8:]
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
        string = ('!!! MalFormed Packet: %s' % self.position)
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
        try:
            if not self.process_openflow_header(of_header):
                return 0

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
                libs.tcpiplib.prints.print_headers(pkt)
                pkt.printed_header = True
            # Print OpenFlow header - version independent
            libs.tcpiplib.prints.print_openflow_header(self.ofp)
            # Print OpenFlow message body
            self.ofp.prints()
            print()
