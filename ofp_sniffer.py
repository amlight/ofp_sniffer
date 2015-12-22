#!/usr/bin/env python

'''
    This code acts as an OpenFlow troubleshoot toolkit: it acts as a sniffer,
    a topology validator and as an OpenFlow message checker, to make sure the
    ONF standards are being followed.

    Despite of ONF standards, this code also supports OpenVSwitch/NICIRA
    OpenFlow type.

    More info on how to use it: www.sdn.amlight.net

    Current version: 0.2

    Author: Jeronimo Bezerra <jab@amlight.net>

'''
import datetime
import pcapy
import sys
from gen.tcpip import get_ethernet_frame, get_ip_packet, \
    get_tcp_stream, get_openflow_header
import gen.cli
import gen.proxies
from gen.prints import print_headers, print_openflow_header
from of10.parser import process_ofp_type
import of10.dissector
from of13.parser import process_ofp_type13


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
            parse_packet(packet, datetime.datetime.now(),
                         header.getlen(), header.getcaplen(),
                         print_options, sanitizer)
    except KeyboardInterrupt:
        print gen.proxies.close()
        print 'Exiting...'
        sys.exit(0)
    except Exception as exception:
        print exception
        return


def sanitizer_filters(of_header, date, getlen, caplen, header_size,
                      eth, ip, tcp, sanitizer):
    '''
        If -F was provided, use filters specified
    '''
    if (of_header['version'] == -1):
        print ('h_size : %s - caplen: %s ' % (header_size, caplen))
        print_headers(1, date, getlen, caplen, eth, ip, tcp)
        print 'OpenFlow header not complete. Ignoring packet.'
        return 0

    # OF Versions supported through json file (-F)
    name_version = of10.dissector.get_ofp_version(of_header['version'])
    supported_versions = []
    for version in sanitizer['allowed_of_versions']:
        supported_versions.append(version)
    if name_version not in supported_versions:
        return 0

    # OF Types to be ignored through json file (-F)
    rejected_types = sanitizer['allowed_of_versions'][name_version]
    if of_header['type'] in rejected_types['rejected_of_types']:
        return 0

    return 1


def parse_packet(packet, date, getlen, caplen, print_options, sanitizer):
    '''
        This functions gets the raw packet and dissassembly it.
        Only TCP + OpenFlow are analysed. Others are discarted
    '''
    eth = get_ethernet_frame(packet)

    # If protocol is no IP(8) returns
    if (eth['protocol'] != 8):
        return

    ip = get_ip_packet(packet, eth['length'])

    # If protocol is not TCP, returns
    if (ip['protocol'] != 6):
        return

    header_size = ip['length'] + eth['length']
    tcp = get_tcp_stream(packet, header_size)

    # If TCP flag is not PUSH, return
    if (tcp['flag_psh'] != 8):
        return

    # Now let's process all OpenFlow packets in the payload
    header_size = header_size + tcp['length']
    remaining_bytes = caplen - header_size

    print_header_once = 0
    start = header_size

    # If there is less than 8 bytes, it is because it is fragment.
    # There is no support for fragmented packet at this time
    while (remaining_bytes >= 8):
        of_header = get_openflow_header(packet, start)

        # If -F was passed...
        if len(sanitizer['allowed_of_versions']) != 0:
            result = sanitizer_filters(of_header, date, getlen, caplen,
                                       header_size, eth, ip, tcp, sanitizer)
            if result == 0:
                return

        # If not OpenFlow version 1.0 or 1.3 return
        if of_header['version'] not in [1, 4]:
            return

        # In case there are multiple flow_mods
        remaining_bytes = remaining_bytes - of_header['length']

        # Starts printing
        if print_header_once == 0:
            print_headers(print_options, date, getlen, caplen, eth, ip, tcp)
            print_header_once = 1

        # Prints the OpenFlow header, it doesn't matter the OF version
        print_openflow_header(of_header)

        print_options['device_ip'] = ip['d_addr']
        print_options['device_port'] = tcp['dest_port']

        # Process and Print OF body
        # OF_Header lenght = 8
        start = start + 8
        this_packet = packet[start:start+of_header['length'] - 8]

        # If OpenFlow version is 1.0
        if of_header['version'] is 1:
            if not process_ofp_type(of_header['type'], this_packet, 0,
                                    of_header['xid'], print_options, sanitizer):

                print ('%s OpenFlow OFP_Type %s unknown \n' %
                       (of_header['xid'], of_header['type']))
                return
            else:
                # Get next packet
                start = start + (of_header['length'] - 8)

        # If OpenFlow version is 1.3
        elif of_header['version'] is 4:
            # Process and Print OF body
            # OF_Header lenght = 8
            if not process_ofp_type13(of_header['type'], this_packet, 0,
                                      of_header['xid'], print_options,
                                      sanitizer):
                print ('%s OpenFlow OFP_Type %s not dissected yet \n' %
                       (of_header['xid'], of_header['type']))
                return
            else:
                # Get next packet
                start = start + (of_header['length'] - 8)

        # Do not process extra data from Hello and Error.
        # Maybe in the future.
        if (of_header['type'] == 0 or of_header['type'] == 1):
            print
            return

        print

if __name__ == "__main__":
    main(sys.argv)
