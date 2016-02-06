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


def main(argv):
    '''
        This is the main function
    '''
    print_options, infilter, sanitizer, dev, capfile = gen.cli.get_params(argv)
    try:
        if len(capfile) > 0:
            print "Using file %s " % capfile
            cap = pcapy.open_offline(capfile)
        else:
            print "Sniffing device %s" % dev
            cap = pcapy.open_live(dev, 65536, 1, 0)

        main_filter = " port 6633 "
        cap.setfilter(main_filter + infilter)

        ctr = 1
        # start sniffing packets
        while(1):
            (header, packet) = cap.next()
            time = datetime.datetime.now()
            pkt = Packet(packet, print_options, sanitizer)
            pkt.process_header(header.getlen(), header.getcaplen(), time)
            if pkt.openflow_packet:
                print 'Packet #' + str(ctr)
                ctr += 1
                pkt.process_openflow_messages()
                pkt.print_packet()
            del pkt

    except KeyboardInterrupt:
        print 'Exiting...'
        sys.exit(0)
    except Exception as exception:
        print exception
        return


if __name__ == "__main__":
    main(sys.argv)
