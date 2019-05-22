"""
    This is the class for the OpenFlow message. With the python-openflow
    library, introduced in the version 0.4, this class became much
    simpler.
"""
from libs.tcpiplib.tcpip import get_openflow_header
from pyof.v0x01.common.utils import unpack_message as unpack10
from pyof.v0x04.common.utils import unpack_message as unpack13
import libs.core.filters
import libs.tcpiplib.packet
import libs.tcpiplib.prints
from libs.openflow.of10.prints import prints_ofp as prints_ofp10
from libs.openflow.of13.prints import prints_ofp as prints_ofp13


class OFMessage(object):
    """
        Used to process all data regarding this OpenFlow message. With
        the python-openflow (pyof) lib, only one variable became
        necessary.
    """
    def __init__(self, this_packet):
        """
            Instantiate OFMessage class
            Args:
                self: this class
                this_packet: OpenFlow msg in binary format
        """
        try:
            version = get_openflow_header(this_packet, 0)

            if version['version'] == 1:
                self.ofp = unpack10(this_packet)
            elif version['version'] == 4:
                self.ofp = unpack13(this_packet)
            else:
                self.ofp = 0

        except:
            # if there is a problem with the python-openflow
            # just set the self.ofp to 0. It will be ignored
            # by the Packet().add_of_msg_to_list
            self.ofp = 0

    def print_packet(self, pkt):
        """
            Generic printing function
            Args:
                pkt: Packet class
        """
        # Check if there is any printing filter
        if not libs.core.filters.filter_msg(self):
            # Only prints TCP/IP header once
            # A TCP/IP packet might contain multiple OpenFlow messages
            if pkt.printed_header is False:
                libs.tcpiplib.prints.print_headers(pkt)
                pkt.printed_header = True
            # Print OpenFlow header - version independent
            libs.tcpiplib.prints.print_openflow_header(self.ofp)
            # Print OpenFlow message body
            if self.ofp.header.version == 1:
                prints_ofp10(self.ofp)
            elif self.ofp.header.version == 4:
                prints_ofp13(self.ofp)
            print()
