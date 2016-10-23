#!/usr/bin/env python

"""
    This code is an OpenFlow troubleshooting tool: it acts as a sniffer
    and as an OpenFlow message checker, to make sure the
    ONF standards are being followed.

    More info on how to use it: www.sdn.amlight.net

    Current version: 0.3

    Author: Jeronimo Bezerra <jab@amlight.net>
"""

import datetime
import sys
import gen.cli
from gen.packet import Packet
from gen.check_dep import check_dependencies


# Global Variable
# Others are instantiated later: cap, position, print_options, sanitizer
ctr = 1


def process_packet(header, packet):
    """
        Every packet captured by cap.loop is then processed here.
        If packets are bigger than 62 Bytes, we process. If it is 0, means there is
            no more packets. If it is something in between, it is a fragment,
            we ignore for now.
        Args:
            header: header of the captured packet
            packet: packet captured from file or interface
    """
    global ctr  # packet counter

    if len(packet) >= 62 and position_defined():
        time = datetime.datetime.now()
        # global variables: print_options, sanitizer, ctr
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


def position_defined():
    """
        In case user wants to see a specific packet inside a
            specific pcap file, provide file name with the position
            -r file.pcap:position
        Returns:
            True if ctr is good
            False: if ctr is not good
    """
    return (True if ctr == position else False) if position > 0 else True


def main():
    """
        This is how it starts: cap.loop continuously capture packets w/ pcapy
        print_options and sanitizer are global variables
        Exits:
            0 - Normal, reached end of file
            1 - Normal, user requested with CRTL + C
            2 - Error
            3 - Interface or file not found
    """
    exit_code = 0
    try:
        cap.loop(-1, process_packet)
    except KeyboardInterrupt:
        exit_code = 1
    except Exception as exception:
        print 'Error: %s ' % exception
        exit_code = 2
    finally:
        print 'Exiting...'
        sys.exit(exit_code)


if __name__ == "__main__":
    # Test dependencies first
    if not check_dependencies():
        sys.exit(2)
    # Get CLI params and call the pcapy loop
    cap, position, print_options, sanitizer = gen.cli.get_params(sys.argv)
    main()
