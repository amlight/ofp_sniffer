"""

"""

import libs.filters
import libs.gen.proxies
import libs.tcpiplib.packet
import libs.tcpiplib.prints
import libs.openflow.instantiate
from libs.debugging import debugclass
from pyof.v0x01.common.utils import unpack_message

from libs.openflow.of10.prints import prints_ofp


@debugclass
class OFMessage(object):
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
        self.ofp = unpack_message(this_packet)

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
            prints_ofp(self.ofp)
            print()
