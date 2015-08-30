import datetime
import pcapy
import sys
from ofp_prints_v10 import print_layer1, print_layer2, print_layer3, \
    print_tcp, print_openflow_header, print_minimal
import ofp_parser_v10
from ofp_tcpip_parser.py import get_ethernet_frame, get_ip_packet, \
    get_tcp_stream, get_openflow_header

print_min = 1


def main(argv):
    '''
        This is the main function
    '''
    dev = "eth0"
    print "Sniffing device " + dev
    cap = pcapy.open_live(dev, 65536, 1, 0)
    cap.setfilter(" port 6633")

    # start sniffing packets
    while(1):
        (header, packet) = cap.next()
        parse_packet(packet, datetime.datetime.now(), header.getlen(),
                     header.getcaplen())


def parse_packet(packet, date, getlen, caplen):
    '''
        This functions gets the raw packet and dissassembly it.
        Only TCP + OpenFlow are analysed. Others are discarted
    '''

    src_mac, dst_mac, eth_protocol, eth_length = get_ethernet_frame(packet)

    # If protocol is no IP(8) returns
    if (eth_protocol != 8):
        return

    version, ihl, iph_length, ttl, protocol, s_addr, \
        d_addr = get_ip_packet(packet, eth_length)

    # If protocol is not TCP, returns
    if (protocol != 6):
        return

    header_size = iph_length + eth_length
    source_port, dest_port, sequence, acknowledgement, tcph_length, flag_cwr, \
        flag_ece, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, \
        flag_fyn = get_tcp_stream(packet, header_size)

    # If TCP flag is not PUSH, return
    if (flag_psh != 8):
        return

    # Now let's process all OpenFlow packets in the payload
    header_size = header_size + tcph_length
    remaining_bytes = caplen - header_size

    print_header_once = 0
    start = header_size

    # If there is less than 8 bytes, it is because it is fragment.
    # There is no support for fragmented packet at this time
    while (remaining_bytes >= 8):
        of_version, of_type, of_length, \
            of_xid = get_openflow_header(packet, start)

        if (of_version != -1):
            # In case there are multiple flow_mods
            remaining_bytes = remaining_bytes - of_length

            # If it is PacketIn, PacketOut, StatsReq, StatsRes or BarrierReq/Res
            # we ignore for now
            if of_type == 10 or of_type == 13 or of_type == 16\
               or of_type == 17 or of_type == 18 or of_type == 19:
                return

            # Starts printing
            if print_header_once == 0:
                if print_min == 1:
                    print_minimal(date, s_addr, source_port, d_addr, dest_port)
                else:
                    print_layer1(date, getlen, caplen)
                    print_layer2(dst_mac, src_mac, eth_protocol)
                    print_layer3(version, ihl, ttl, protocol, s_addr, d_addr)
                    print_tcp(source_port, dest_port, sequence, acknowledgement,
                              tcph_length, flag_cwr, flag_ece, flag_urg,
                              flag_ack, flag_psh, flag_rst, flag_syn, flag_fyn)
                print_header_once = 1

            # Prints the OpenFlow header, it doesn't matter the OF version
            print_openflow_header(of_version, of_type, of_length, of_xid)

            # If OpenFlow version is 1
            if of_version == int('1', 16):
                # Process and Print OF body
                # OF_Header lenght = 8
                start = start + 8
                this_packet = packet[start:start+of_length-8]
                if not ofp_parser_v10.process_ofp_type(of_type,
                                                       this_packet,
                                                       0, of_xid):
                    print str(of_xid) + ' OpenFlow OFP_Type ' \
                        + str(of_type) + ' not implemented \n'
                    return
                else:
                    # Get next packet
                    start = start + of_length - 8
            else:
                print 'Only OpenFlow 1.0 is supported \n'
                return

            # Do not process extra data from Hello and Error.
            # Maybe in the future.
            if (of_type == 0 or of_type == 1):
                print
                return

        else:
            print 'h_size : ' + str(header_size) + ' and caplen: ' + \
                str(caplen) + ' remaining_bytes = ' + str(remaining_bytes)
            print_layer1(date, getlen, caplen)
            print_layer2(dst_mac, src_mac, eth_protocol)
            print_layer3(version, ihl, ttl, protocol, s_addr, d_addr)
            print_tcp(source_port, dest_port, sequence,
                      acknowledgement, tcph_length,
                      flag_cwr, flag_ece, flag_urg, flag_ack,
                      flag_psh, flag_rst, flag_syn, flag_fyn)
            print 'OpenFlow header not complete. Ignoring packet.'

        print


if __name__ == "__main__":
    main(sys.argv)
