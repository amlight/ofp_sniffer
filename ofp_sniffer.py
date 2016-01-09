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

        # start sniffing packets
        while(1):
            (header, packet) = cap.next()
            time = datetime.datetime.now()
            pkt = Packet(packet, print_options, sanitizer)
            pkt.process_header(header.getlen(), header.getcaplen(), time)
            if pkt.openflow_packet:
                pkt.process_openflow_body()
            # Prints
            del pkt

    except KeyboardInterrupt:
        print 'Exiting...'
        sys.exit(0)
    except Exception as exception:
        print exception
        return


#def sanitizer_filters(of_header, date, getlen, caplen, header_size,
#                      eth, ip, tcp, sanitizer):
#    '''
#        If -F was provided, use filters specified
#    '''
#    if (of_header['version'] == -1):
#        print ('h_size : %s - caplen: %s ' % (header_size, caplen))
#        print_headers(1, date, getlen, caplen, eth, ip, tcp)
#        print 'OpenFlow header not complete. Ignoring packet.'
#        return 0
#
#    # OF Versions supported through json file (-F)
#    name_version = of10.dissector.get_ofp_version(of_header['version'])
#    supported_versions = []
#    for version in sanitizer['allowed_of_versions']:
#        supported_versions.append(version)
#    if name_version not in supported_versions:
#        return 0
#
#    # OF Types to be ignored through json file (-F)
#    rejected_types = sanitizer['allowed_of_versions'][name_version]
#    if of_header['type'] in rejected_types['rejected_of_types']:
#        return 0
#
#    return 1


if __name__ == "__main__":
    main(sys.argv)
