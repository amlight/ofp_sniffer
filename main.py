import socket
from struct import unpack
import datetime
import pcapy
import sys
from termcolor import colored
import ofp_sniffer


def main(argv):
    # list all devices
    devices = pcapy.findalldevs()
    print devices

    # ask user to enter device name to sniff
    print "Available devices are :"
    for d in devices:
        print d

    dev = raw_input("Enter device name to sniff: ")

    print "Sniffing device " + dev

    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    cap = pcapy.open_live(dev, 65536, 1, 0)
    cap.setfilter(" port 6633")

    # start sniffing packets
    while(1):
        (header, packet) = cap.next()
        parse_packet(packet, datetime.datetime.now(), header.getlen(),
                     header.getcaplen())


# Convert a string of 6 characters of ethernet address into a dash
# separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]),
                                           ord(a[3]), ord(a[4]), ord(a[5]))
    return b


def print_layer1(date, getlen, caplen):
    print ('%s: captured %d bytes, truncated to %d bytes' %
           (date, getlen, caplen))


def print_layer2(dst_mac, src_mac, eth_protocol):
    print 'Destination MAC: ' + eth_addr(dst_mac) + ' Source MAC: ' + \
        eth_addr(src_mac) + ' Protocol: ' + str(eth_protocol)


def print_layer3(version, ihl, ttl, protocol, s_addr, d_addr):
    print 'IP Version: ' + str(version) + ' IP Header Length: ' + str(ihl) \
        + ' TTL: ' + str(ttl) + ' Protocol: ' + str(protocol) \
        + ' Source Address: ' + colored(str(s_addr), 'blue') + ' Destination Address: ' \
        + colored(str(d_addr), 'blue')


def print_tcp(source_port, dest_port, sequence, acknowledgement, tcph_length,
              flags, flag_cwr, flag_ece, flag_urg, flag_ack, flag_psh, flag_rst,
              flag_syn, flag_fyn):
    print 'TCP Source Port: ' + str(source_port) + ' Dest Port: ' + \
        str(dest_port) + ' Sequence Number: ' + str(sequence) + \
        ' Acknowledgement: ' + str(acknowledgement) + \
        ' TCP header length: ' + str(tcph_length * 4) + ' Flags: ' + str(flags) +  \
        ' \nFlags: CWR: ' + str(flag_cwr) + ' ECE: ' + str(flag_ece) + ' URG: ' + str(flag_urg) + \
        ' ACK: ' + str(flag_ack) + ' PSH: ' + str(flag_psh) + ' RST: ' + str(flag_rst) + ' SYN: ' + \
        str(flag_syn) + ' FYN: ' + str(flag_fyn)


def print_openflow_header(of_version, of_type, of_length, of_xid):
    print 'OpenFlow Version: ' + str(of_version) + ' Type: ' + str(of_type) \
        + ' Length: ' + str(of_length) + ' XID: ' + str(colored(of_xid, 'red'))


# function to parse a packet
def parse_packet(packet, date, getlen, caplen):

    # parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        # TCP protocol
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
            flags = tcph[5]  # Ignoring NS
            flag_cwr = flags & 0x80
            flag_ece = flags & 0x40
            flag_urg = flags & 0x20
            flag_ack = flags & 0x10
            flag_psh = flags & 0x08
            flag_rst = flags & 0x04
            flag_syn = flags & 0x02
            flag_fyn = flags & 0x01

            h_size = eth_length + iph_length + tcph_length * 4

        # If TCP payload has content (PSH = 8)
        if flag_psh == 8:
            # OpenFlow packets
            # OF Header has 8 bytes
            of_header = packet[h_size:8+h_size]
            ofh = unpack('!BBHL', of_header)
            of_version = ofh[0]
            of_type = ofh[1]
            of_length = ofh[2]
            of_xid = ofh[3]

            # We are interested on Flow_MOD only - Type = 14
            # FLOW_MOD is composed by Match (40 Bytes) + Cookies + ...
            if of_type == 14:
                of_match = packet[h_size+8:h_size+8+40]
                ofm = unpack('!LH6s6sHBBHBBHLLHH', of_match)
                ofm_wildcards = ofm[0]
                ofm_in_port = ofm[1]
                ofm_dl_src = ofm[2]
                ofm_dl_dst = ofm[3]
                ofm_dl_vlan = ofm[4]
                ofm_pcp = ofm[5]
                ofm_pad = ofm[6]
                ofm_dl_type = ofm[7]
                ofm_nw_tos = ofm[8]
                ofm_nw_prot = ofm[9]
                ofm_pad2 = ofm[10]
                ofm_nw_src = ofm[11]
                ofm_nw_dst = ofm[12]
                ofm_tp_src = ofm[13]
                ofm_tp_dst = ofm[14]

                print_layer1(date, getlen, caplen)
                print_layer2(packet[0:6], packet[6:12], eth_protocol)
                print_layer3(version, ihl, ttl, protocol, s_addr, d_addr)
                print_tcp(source_port, dest_port, sequence, acknowledgement,
                          tcph_length, tcph[5], flag_cwr, flag_ece, flag_urg,
                          flag_ack, flag_psh, flag_rst, flag_syn, flag_fyn)
                print_openflow_header(of_version, of_type, of_length, of_xid)
                ofp_sniffer.print_ofp_match(of_xid, ofm_wildcards, ofm_in_port,
                                            eth_addr(ofm_dl_src),
                                            eth_addr(ofm_dl_dst),
                                            ofm_dl_vlan, ofm_dl_type, ofm_pcp,
                                            ofm_pad, ofm_nw_tos, ofm_nw_prot,
                                            ofm_pad2, ofm_nw_src, ofm_nw_dst,
                                            ofm_tp_src, ofm_tp_dst)

                # OFP Body
                of_mod_body = packet[h_size+48:h_size+48+24]
                ofmod = unpack('!8sHHHHLHH', of_mod_body)
                ofmod_cookie = ofmod[0] if not len(ofmod[0]) else 0
                ofmod_command = ofmod[1]
                ofmod_idle_timeout = ofmod[2]
                ofmod_hard_timeout = ofmod[3]
                ofmod_prio = ofmod[4]
                ofmod_buffer_id = ofmod[5]
                ofmod_out_port = ofmod[6]
                ofmod_flags = ofmod[7]

                ofp_sniffer.print_ofp_body(of_xid, ofmod_cookie, ofmod_command,
                                           ofmod_idle_timeout,
                                           ofmod_hard_timeout,
                                           ofmod_prio, ofmod_buffer_id,
                                           ofmod_out_port, ofmod_flags)

                # Actions: Header, Port plus each possible
                start = h_size+72
                while (1):
                    ofp_action = packet[start:start+4]
                    if len(ofp_action) > 0:
                        ofa = unpack('!HH', ofp_action)
                        ofa_type = ofa[0]
                        ofa_length = ofa[1]
                        ofa_action_payload = packet[start+4:start+8]
                        ofp_sniffer.print_ofp_action(of_xid, ofa_type, ofa_length, ofa_action_payload)
                        start = start + 4
                    else:
                        break

                print

            # OpenFlow Error
            if of_type == 1:
                of_error = packet[h_size+8:h_size+8+4]
                ofe = unpack('!HH', of_error)
                ofe_type = ofe[0]
                ofe_code = ofe[1]

                print_layer1(date, getlen, caplen)
                print_layer2(packet[0:6], packet[6:12], eth_protocol)
                print_layer3(version, ihl, ttl, protocol, s_addr, d_addr)
                print_tcp(source_port, dest_port, sequence, acknowledgement,
                          tcph_length, tcph[5], flag_cwr, flag_ece, flag_urg,
                          flag_ack, flag_psh, flag_rst, flag_syn, flag_fyn)
                print_openflow_header(of_version, of_type, of_length, of_xid)

                nameCode, typeCode = ofp_sniffer.get_ofp_error(ofe_type, ofe_code)
                print str(of_xid) + ' OpenFlow Error - Type: ' + colored(nameCode, 'red') + \
                    ' Code: ' + colored(typeCode, 'red')

                print

if __name__ == "__main__":
    main(sys.argv)
