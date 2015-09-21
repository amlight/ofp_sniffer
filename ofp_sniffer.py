#!/usr/bin/env python

import datetime
import pcapy
import sys
from ofp_prints_v10 import print_headers, print_openflow_header
from ofp_parser_v10 import process_ofp_type
from ofp_tcpip_parser import get_ethernet_frame, get_ip_packet, \
    get_tcp_stream, get_openflow_header
import ofp_cli


def main(argv):
    '''
        This is the main function
    '''
    print_options, infilter, sanitizer, dev, capfile = ofp_cli.get_params(argv)
    try:
        print "Sniffing device " + dev
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
        print 'Exiting...'
        sys.exit(0)
    except Exception as exception:
        print exception
        return


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

        if (of_header['version'] == -1):
            print 'h_size : ' + str(header_size) + ' and caplen: ' + \
                str(caplen) + ' remaining_bytes = ' + str(remaining_bytes)
            print_headers(1, date, getlen, caplen, eth, ip, tcp)
            print 'OpenFlow header not complete. Ignoring packet.'
            return

        # In case there are multiple flow_mods
        remaining_bytes = remaining_bytes - of_header['length']

        # OF Types to be ignored through json file (-F)
        rejected_types = sanitizer['filtered_of_types']
        if of_header['type'] in rejected_types:
            return

        # Starts printing
        if print_header_once == 0:
            print_headers(print_options, date, getlen, caplen, eth, ip, tcp)
            print_header_once = 1

        # Prints the OpenFlow header, it doesn't matter the OF version
        print_openflow_header(of_header)

        print_options['device_ip'] = ip['d_addr']
        print_options['device_port'] = tcp['dest_port']

        # If OpenFlow version is 1
        if of_header['version'] == int('1', 16):
            # Process and Print OF body
            # OF_Header lenght = 8
            start = start + 8
            this_packet = packet[start:start+of_header['length'] - 8]
            if not process_ofp_type(of_header['type'], this_packet, 0,
                                    of_header['xid'], print_options):
                print str(of_header['xid']) + ' OpenFlow OFP_Type ' \
                    + str(of_header['type']) + ' not dissected \n'
                return
            else:
                # Get next packet
                start = start + (of_header['length'] - 8)
        else:
            print 'Only OpenFlow 1.0 is supported \n'
            return

        # Do not process extra data from Hello and Error.
        # Maybe in the future.
        if (of_header['type'] == 0 or of_header['type'] == 1):
            print
            return

        print


if __name__ == "__main__":
    main(sys.argv)
