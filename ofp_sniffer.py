#!/usr/bin/env python

import datetime
import pcapy
import sys
from ofp_prints_v10 import print_headers, print_openflow_header
import ofp_parser_v10
from ofp_tcpip_parser import get_ethernet_frame, get_ip_packet, \
    get_tcp_stream, get_openflow_header
import ofp_cli


def main(argv):
    '''
        This is the main function
    '''
    print_min, infilter, sanitizer, dev, capfile = ofp_cli.get_params(argv)

    try:
        print "Sniffing device " + dev
        cap = pcapy.open_live(dev, 65536, 1, 0)
        main_filter = " port 6633 "
        cap.setfilter(main_filter + infilter)

        # start sniffing packets
        while(1):
            (header, packet) = cap.next()
            parse_packet(packet, datetime.datetime.now(),
                         header.getlen(), header.getcaplen(), print_min)
    except Exception as exception:
        print exception
        return


def parse_packet(packet, date, getlen, caplen, print_min):
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

        # If it is PacketIn, PacketOut, StatsReq, StatsRes or BarrierReq/Res
        # we ignore for now
        rejected_types = [2, 3, 10, 13, 16, 17, 18, 19]
        if of_header['type'] in rejected_types:
            return

        # Starts printing
        if print_header_once == 0:
            print_headers(print_min, date, getlen, caplen, eth, ip, tcp)
            print_header_once = 1

        # Prints the OpenFlow header, it doesn't matter the OF version
        print_openflow_header(of_header)

        # If OpenFlow version is 1
        if of_header['version'] == int('1', 16):
            # Process and Print OF body
            # OF_Header lenght = 8
            start = start + 8
            this_packet = packet[start:start+of_header['length'] - 8]
            if not ofp_parser_v10.process_ofp_type(of_header['type'],
                                                   this_packet,
                                                   0, of_header['xid']):
                print str(of_header['xid']) + ' OpenFlow OFP_Type ' \
                    + str(of_header['type']) + ' not implemented \n'
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
