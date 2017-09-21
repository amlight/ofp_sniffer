#!/usr/bin/env python3.6

"""
    This code is the AmLight OpenFlow Sniffer

    Author: AmLight Dev Team <dev@amlight.net>
"""
import sys
import yaml
import logging.config
import threading
from libs.core.printing import PrintingOptions
from libs.core.sanitizer import Sanitizer
from libs.core.topo_reader import TopoReader
from libs.core.cli import get_params
from libs.core.save_to_file import save_to_file
from libs.core.custom_exceptions import *
from libs.gen.packet import Packet
from apps.oess_fvd import OessFvdTracer
from apps.ofp_stats import OFStats
from apps.ofp_proxies import OFProxy
from apps.influx_client import InfluxClient


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
        self.influx = None
        self.trigger_event = threading.Event()
        self.cap = None
        self.packet_number = None
        self.load_apps = dict()
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
            self.oft = OessFvdTracer(self.load_apps['oess_fvd'])

        if 'statistics' in self.load_apps:
            self.stats = OFStats()
            if 'influx' in self.load_apps:
                self.influx = InfluxClient(trigger_event=self.trigger_event)

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

        except EndOfPcapFile:
            exit_code = 3

        except KeyboardInterrupt:
            exit_code = 1

        except Exception as exception:
            print('Error on packet %s: %s ' % (self.packet_count, exception))
            exit_code = 2

        finally:

            if 'statistics' in self.load_apps:
                #  If OFP_Stats is running, set a timer
                #  before closing the app. Useful in cases
                #  where the ofp_sniffer is reading from a
                #  pcap file instead of a NIC.
                time.sleep(200)
                #pass

            print('Exiting with code: %s' % exit_code)
            # gracefully shut down
            if 'influx' in self.load_apps:
                self.influx.stop_event.set()
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

        if len(packet) >= 62:

            # Verify if user asked for just one specific packet
            if self.was_packet_number_defined():
                if not self.is_the_packet_number_specified():
                    self.packet_count += 1
                    return

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
            if self.influx:
                # tell influx to wake up and update immediately
                self.trigger_event.set()

            del pkt

            if self.is_the_packet_number_specified():
                # If a specific packet was selected, end here.
                raise EndOfPcapFile

        elif len(packet) is 0:
            return 3

        self.packet_count += 1

    def was_packet_number_defined(self):
        """
            In case user wants to see a specific packet inside a
            specific pcap file, provide file name with the specific
            packet number after ":"
                -r file.pcap:packet_number
            Returns:
                True if a packet number was specified
                False: if a packet number was not specified
        """
        if self.packet_number != 0:
            return True
        return False

    def is_the_packet_number_specified(self):
        """
            If user wants to see a specific packet inside a
            specific pcap file and the packet_count is that
            number, return True. Otherwise, return false

            Returns:
                True if packet_count matches
                False: if packet_count does not match
        """
        return True if self.packet_count == self.packet_number else False


def main():
    """
        Main function.
        Instantiates RunSniffer and run it
    """
    try:
        logging.config.dictConfig(yaml.load(open('logging.yml', 'r')))
        logger = logging.getLogger(__name__)
        sniffer = RunSniffer()
        logger.info("OFP_Sniffer started.")
        sniffer.run()

    except ErrorFilterFile as msg:
        print(msg)
        sys.exit(4)

    except FileNotFoundError as msg:
        print(msg)
        sys.exit(5)


if __name__ == "__main__":
    main()
