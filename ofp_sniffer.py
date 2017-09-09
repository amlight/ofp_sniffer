#!/usr/bin/env python

"""
    This code is the AmLight OpenFlow Sniffer

    Current version: 0.4

    Author: AmLight Dev Team <dev@amlight.net>
"""
import time
import sys
from libs.core.printing import PrintingOptions
from libs.core.sanitizer import Sanitizer
from libs.core.topo_reader import TopoReader
from libs.core.cli import get_params
from libs.core.save_to_file import save_to_file
from libs.gen.packet import Packet
from apps.oess_fvd import OessFvdTracer
from apps.ofp_stats import OFStats
from apps.ofp_proxies import OFProxy


class RunSniffer(object):
    """
        The RunSniffer class is the main class for the OpenFlow Sniffer.
        This class instantiate all auxiliary classes, captures the packets,
        instantiate new OpenFlow messages and triggers all applications.
    """
    def __init__(self):
        self.printing_options = PrintingOptions()
        self.sanitizer = Sanitizer()
        self.oft = None
        self.stats = None
        self.cap = None
        self.packet_number = None
        self.load_apps = []
        self.packet_count = 1
        self.topo_reader = TopoReader()
        self.save_to_file = None
        self.ofp_proxy = None
        self.load_config()

    def load_config(self):
        """
            Parses the parameters received and instantiates the
            apps requested.
        """
        # Get CLI params and call the pcapy loop
        self.cap, self.packet_number, \
            self.load_apps, sanitizer, \
            topo_file, is_to_save = get_params(sys.argv)
        self.sanitizer.process_filters(sanitizer)

        # Load TopologyReader
        self.topo_reader.readfile(topo_file)

        # Save to File
        self.save_to_file = save_to_file(is_to_save)

        # Start Apps
        self.ofp_proxy = OFProxy()

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

        #  Debug:
        #  self.cap.loop(-1, self.process_packet)
        try:
            self.cap.loop(-1, self.process_packet)

            if 'statistics' in self.load_apps:
                #  If OFP_Stats is running, set a timer
                #  before closing the app. Useful in cases
                #  where the ofp_sniffer is reading from a
                #  pcap file instead of a NIC.
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

            if pkt.reconnect_error:
                if isinstance(self.stats, OFStats):
                    # OFStats counts reconnects
                    self.stats.process_packet(pkt)

            elif pkt.is_openflow_packet:
                valid_result = pkt.process_openflow_messages()
                if valid_result:

                    # Apps go here:
                    if isinstance(self.oft, OessFvdTracer):
                        # FVD_Tracer does not print the packets
                        self.oft.process_packet(pkt)

                    if isinstance(self.ofp_proxy, OFProxy):
                        # OFP_PROXY associates IP:PORT to DPID
                        self.ofp_proxy.process_packet(pkt)

                    if isinstance(self.stats, OFStats):
                        # OFStats print the packets
                        self.stats.process_packet(pkt)

                    if not isinstance(self.oft, OessFvdTracer):
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

        return True


def main():
    """
        Main function.
        Instantiates RunSniffer and run it
    """
    sniffer = RunSniffer()
    sniffer.run()


if __name__ == "__main__":
    main()
