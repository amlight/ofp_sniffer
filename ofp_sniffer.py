#!/usr/bin/env python

"""
    This code acts as an OpenFlow troubleshoot toolkit: it acts as a sniffer
    and as an OpenFlow message checker, to make sure the
    ONF standards are being followed.

    More info on how to use it: www.sdn.amlight.net

    Current version: 0.3

    Author: Jeronimo Bezerra <tcpiplib@amlight.net>
"""

import datetime
import sys
import gen.cli
from gen.packet import Packet


ctr = 1


def process_packet(header, packet):
    """
        Every packet captured by cap.loop is then processed here.
        If packets are bigger than 62, we process. If it is 0, means there is
            no more packets. If it is something in between, it is a fragment,
            just ignore.
    Args:
        header: header of the captured packet
        packet: packet captured from file or interface
    """
    global ctr  # packet counter
    if len(packet) >= 62:
        time = datetime.datetime.now()
        pkt = Packet(packet, print_options, sanitizer, ctr)
        pkt.process_packet_header(header, time)
        if pkt.openflow_packet:
            result = pkt.process_openflow_messages()
            if result is 1:
                pkt.print_packet()
        del pkt
    elif len(packet) is 0:
        sys.exit(0)
    ctr += 1


def main(argv):
    """
        This is how it starts: cap.loop continuously capture packets w/ pcapy
        print_options and sanitizer are global variables
    """
    cap.loop(-1, process_packet)
#    try:
#        cap.loop(-1, process_packet)
#    except KeyboardInterrupt:
#        print 'Exiting...'
#        sys.exit(0)
#    except Exception as exception:
#        print exception

if __name__ == "__main__":
    cap, print_options, sanitizer = gen.cli.get_params(sys.argv)
    main(sys.argv)