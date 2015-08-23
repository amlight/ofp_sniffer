import socket
from struct import unpack
import datetime
import pcapy
import sys
from ofp_prints_v10 import print_layer1, print_layer2, print_layer3, \
    print_tcp, print_openflow_header
import ofp_parser_v10


def main(argv):

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
    # Get Ethernet header - 14 Bytes
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # From EtherType 8, Get IP Header = 20 Bytes
    if eth_protocol == 8:
        ip_header = packet[eth_length:20+eth_length]
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        # From IP Protocol 6, Get TCP Header = 20 Bytes
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
            tcph = unpack('!HHLLBBHHH', tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            flags = tcph[5]  # Ignoring Flag NS
            flag_cwr = flags & 0x80
            flag_ece = flags & 0x40
            flag_urg = flags & 0x20
            flag_ack = flags & 0x10
            flag_psh = flags & 0x08
            flag_rst = flags & 0x04
            flag_syn = flags & 0x02
            flag_fyn = flags & 0x01

            h_size = eth_length + iph_length + tcph_length * 4

            # If TCP payload has content (PSH = 8) ==> OpenFlow packet
            # TODO: Validate if it is a real OpenFlow packet
            if flag_psh == 8:
                # Get OpenFlow Header = 8 Bytes
                of_header = packet[h_size:8+h_size]
                try:
                    ofh = unpack('!BBHL', of_header)
                    of_version = ofh[0]
                    of_type = ofh[1]
                    of_length = ofh[2]
                    of_xid = ofh[3]

                    if of_type == 10 or of_type == 13 or of_type == 16 or of_type == 17\
                       or of_type == 18 or of_type == 19:
                        # If it is PacketIn, PacketOut, StatsReq, StatsRes or
                        # BarrierReq/Res we ignore for now
                        return

                    # Starts printing
                    print_layer1(date, getlen, caplen)
                    print_layer2(packet[0:6], packet[6:12], eth_protocol)
                    print_layer3(version, ihl, ttl, protocol, s_addr, d_addr)
                    print_tcp(source_port, dest_port, sequence, acknowledgement,
                              tcph_length, tcph[5], flag_cwr, flag_ece,
                              flag_urg, flag_ack, flag_psh, flag_rst,
                              flag_syn, flag_fyn)
                    print_openflow_header(of_version, of_type, of_length,
                                          of_xid)

                    # Process and Print OF body
                    if not ofp_parser_v10.process_ofp_type(of_type, packet,
                                                           h_size+8, of_xid):
                        print str(of_xid) + ' OpenFlow OFP_Type ' + str(of_type) + \
                            ' not implemented \n'
                        return

                    print
                except:
                    print_layer1(date, getlen, caplen)
                    print_layer2(packet[0:6], packet[6:12], eth_protocol)
                    print_layer3(version, ihl, ttl, protocol, s_addr, d_addr)
                    print_tcp(source_port, dest_port, sequence, acknowledgement,
                              tcph_length, tcph[5], flag_cwr, flag_ece,
                              flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                              flag_fyn)
                    print 'OpenFlow header not completed. Ignoring packet... '


if __name__ == "__main__":
    main(sys.argv)
