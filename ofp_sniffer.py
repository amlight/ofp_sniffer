#!/usr/bin/env python

'''
    This code acts as an OpenFlow troubleshoot toolkit: it acts as a sniffer,
    a topology validator and as an OpenFlow message checker, to make sure the
    ONF standards are being followed.

    Despite of ONF standards, this code also supports OpenVSwitch/NICIRA
    OpenFlow type.

    More info on how to use it: www.sdn.amlight.net

    Current version: 0.3

    Author: Jeronimo Bezerra <jab@amlight.net>

'''
import datetime
import pcapy
import sys
import gen.cli
from gen.packet import Packet


ctr = 1


def process_packet(header, packet):
    global ctr
    if len(packet) >= 62:
        time = datetime.datetime.now()
        pkt = Packet(packet, print_options, sanitizer, ctr)
        pkt.process_header(header.getlen(), header.getcaplen(), time)
        if pkt.openflow_packet:
            result = pkt.process_openflow_messages()
            if result is 1:
                pkt.print_packet()
        del pkt
    elif len(packet) is 0:
        sys.exit(0)
    ctr += 1


def main(argv):
    '''
        This is the main function
    '''
    cap.loop(-1, process_packet)
    return

if __name__ == "__main__":
    cap, print_options, sanitizer = gen.cli.get_params(sys.argv)
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print 'Exiting...'
        sys.exit(0)
    except Exception as exception:
        print exception
