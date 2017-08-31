#!/usr/bin/env python

"""
    This code is the AmLight OpenFlow Sniffer

    Current version: 0.4

    Author: Jeronimo Bezerra <jab@amlight.net>
"""
import sys
from libs.core.printing import PrintingOptions
import libs.core.cli
from apps.oess_fvd import OessFvdTracer
from apps.ofp_stats import OFStats
from libs.core.sanitizer import Sanitizer
from libs.gen.packet import Packet
from libs.gen.proxies import OFProxy
from libs.core.topo_reader import TopoReader
from pyof.foundation.exceptions import UnpackException


class RunSniffer(object):
    """
        The RunSniffer class is the main class for the OpenFlow Sniffer.
        This class instantiate all auxiliary classes, captures the packets,
        instantiate new OpenFlow messages and triggers all applications.
    """
    def __init__(self):
        self.printing_options = PrintingOptions()
        self.sanitizer = Sanitizer()
        self.ofproxy = OFProxy()
        self.toporeader = TopoReader()
        self.oft = None
        self.stats = None
        self.cap = None
        self.packet_number = None
        self.load_apps = []
        self.packet_count = 1
        self.load_config()

    def load_config(self):
        """
            Parses the parameters received and instantiates the
            apps requested.
        """
        # Get CLI params and call the pcapy loop
        self.cap, self.packet_number, \
            self.load_apps, sanitizer = libs.core.cli.get_params(sys.argv)
        self.sanitizer.process_filters(sanitizer)

        # Start Apps
        if 'oess_fvd' in self.load_apps:
            self.oft = OessFvdTracer()

        if 'statistics' in self.load_apps:
            self.stats = OFStats()

    def run(self):
        """
            cap.loop continuously capture packets w/ pcapy. For every
            captured packet, self.process_packet method is called.
            Exits:
                0 - Normal, reached end of file
                1 - Normal, user requested with CRTL + C
                2 - Error
                3 - Interface or file not found
        """
        exit_code = 0

        #self.cap.loop(-1, self.process_packet)
        try:
            self.cap.loop(-1, self.process_packet)

            # Temporary while testing
            import time
            time.sleep(200)

        except KeyboardInterrupt:
            exit_code = 1

        except Exception as exception:
            print('Error on packet %s: %s ' % (self.packet_count, exception))
            exit_code = 2

        finally:
            print('Exiting...')
            sys.exit(exit_code)

    def process_packet(self, header, packet):
        """
            Every packet captured by cap.loop is then processed here.
            If packets are bigger than 62 Bytes, we process them.
            If it is 0, means there are no more packets. If it is
            something in between, it is a fragment, we ignore for now.
            Args:
                header: header of the captured packet
                packet: packet captured from file or interface
        """
        if len(packet) >= 62 and self.packet_number_defined():

            # DEBUG:
            # print("Packet Number: %s" % self.packet_count)
            pkt = Packet(packet, self.packet_count, header)

            if pkt.is_openflow_packet:
                valid_result = pkt.process_openflow_messages()
                if valid_result:
                    # Apps go here:
                    if isinstance(self.oft, OessFvdTracer):
                        # FVD_Tracer does not print the packets
                        self.oft.process_packet(pkt)
                    else:
                        if isinstance(self.stats, OFStats):
                            # OFStats print the packets
                            self.stats.compute_packet(pkt)

                        # Print Packets
                        pkt.print_packet()

            del pkt

        elif len(packet) is 0:
            sys.exit(0)
        self.packet_count += 1

    def packet_number_defined(self):
        """
            In case user wants to see a specific packet inside a
            specific pcap file, provide file name with the specific
            packet number
                -r file.pcap:packet_number
            Returns:
                True if packet_count matches
                False: if packet_count does not match
        """
        if self.packet_number > 0:
            return True if self.packet_count == self.packet_number else False
        else:
            return True


if __name__ == "__main__":
    sniffer = RunSniffer()
    sniffer.run()
