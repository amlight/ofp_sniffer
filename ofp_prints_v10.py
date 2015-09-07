from termcolor import colored
import ofp_dissector_v10
import socket
import struct


def eth_addr(a):
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]),
                                             ord(a[3]), ord(a[4]), ord(a[5]))
    return mac


def print_headers(print_min, date, getlen, caplen, eth, ip, tcp):
    if print_min == 1:
        print_minimal(date, getlen, ip, tcp)
    else:
        print_layer1(date, getlen, caplen)
        print_layer2(eth)
        print_layer3(ip)
        print_tcp(tcp)


def print_minimal(date, getlen, ip, tcp):
    print str(date) + ' ' + \
        colored(str(ip['s_addr']), 'blue') + ':' + \
        colored(str(tcp['source_port']), 'blue') + ' -> ' + \
        colored(str(ip['d_addr']), 'blue') + ':' + \
        colored(str(tcp['dest_port']), 'blue') + ' Size: ' + \
        str(getlen)


def print_layer1(date, getlen, caplen):
    print ('%s: captured %d bytes, truncated to %d bytes' %
           (date, getlen, caplen))


def print_layer2(eth):
    print ('Destination MAC: %s Source MAC: %s Protocol: %d' %
           (eth_addr(eth['dst_mac']), eth_addr(eth['src_mac']),
            eth['protocol']))


def print_layer3(ip):
    print (('IP Version: %d IP Header Length: %d TTL: %d Protocol: %d '
           'Source Address: %s Destination Address: %s') %
           (ip['version'], (ip['ihl'] * 4), ip['ttl'], ip['protocol'],
            colored(ip['s_addr'], 'blue'),
            colored(ip['d_addr'], 'blue')))


def print_tcp(tcp):
    print ('TCP Source Port: %s Dest Port: %s Sequence Number: %s '
           'Acknowledgement: %s TCP header length: %s Flags: (CWR: %s '
           'ECE: %s URG: %s ACK: %s PSH: %s RST: %s SYN: %s FYN: %s' %
           (tcp['source_port'], tcp['dest_port'], tcp['sequence'],
            tcp['acknowledgement'], (tcp['length']), tcp['flag_cwr'],
            tcp['flag_ece'], tcp['flag_urg'], tcp['flag_ack'], tcp['flag_psh'],
            tcp['flag_rst'], tcp['flag_syn'], tcp['flag_fyn']))


def print_openflow_header(of):
    print ('OpenFlow Version: %s Type: %s Length: %s  XID: %s' %
           (of['version'], of['type'], of['length'], colored(of['xid'], 'red')))


def print_of_hello(of_xid):
    print str(of_xid) + ' OpenFlow Hello'


def print_of_error(of_xid, nameCode, typeCode):
    print str(of_xid) + ' OpenFlow Error - Type: ' + colored(nameCode, 'red') + \
        ' Code: ' + colored(typeCode, 'red')


def get_ip_from_long(long_ip):
    return (socket.inet_ntoa(struct.pack('!L', long_ip)))


def print_ofp_match(xid, ofmatch):
    print str(xid) + ' OpenFlow Flow_Mod(14) Match : ' +\
        'wildcards: ' + str(ofmatch['wildcards'])

    for K in ofmatch:
        print ("'%s': %s " % (K, colored(ofmatch[K], 'green')))

# ' dl_type: ' + colored(str('0x'+format(ofm_dl_type, '02x')), 'green') + \


def print_ofp_body(xid, ofmod_cookie, ofmod_command,
                   ofmod_idle_timeout, ofmod_hard_timeout,
                   ofmod_prio, ofmod_buffer_id,
                   ofmod_out_port, ofmod_flags):
    print str(xid) + ' OpenFlow FLOW_MOD Body - Cookie: ' + \
        str('0x' + format(ofmod_cookie, '02x')) + ' Command: ' + \
        colored(ofp_dissector_v10.get_ofp_command(ofmod_command), 'green') + \
        ' Idle/Hard Timeouts: ' + str(ofmod_idle_timeout) + '/' + \
        str(ofmod_hard_timeout) + ' Priority: ' + str(ofmod_prio) + \
        ' Buffer ID: ' + str('0x' + format(ofmod_buffer_id, '02x')) + \
        ' Out Port: ' + str(ofmod_out_port) + ' Flags: ' + \
        ofp_dissector_v10.get_ofp_flags(ofmod_flags)


def print_ofp_flow_removed(xid, ofrem_cookie, ofrem_priority, ofrem_reason,
                           ofrem_pad, ofrem_duration_sec,
                           ofrem_duration_nsec, ofrem_idle_timeout,
                           ofrem_pad2, ofrem_pad3, ofrem_packet_count,
                           ofrem_byte_count):

    print str(xid) + ' OpenFlow FlowRemoved (11) Body - Cookie: ' + \
        str('0x' + format(ofrem_cookie, '02x')) + ' Priority: ' + \
        str(ofrem_priority) + ' Reason: ' + \
        colored(str(
            ofp_dissector_v10.get_flow_removed_reason(ofrem_reason)), 'green')\
        + ' Pad: ' + str(ofrem_pad) \
        + ' Duration Secs/NSecs ' + str(ofrem_duration_sec) + '/' + \
        str(ofrem_duration_nsec) + ' Idle Timeout: ' + str(ofrem_idle_timeout)\
        + ' Pad2/Pad3: ' + str(ofrem_pad2) + '/' + str(ofrem_pad3) + \
        ' Packet Count: ' + str(ofrem_packet_count) + ' Byte Count: ' + \
        str(ofrem_byte_count)


def print_ofp_action(xid, action_type, length, payload):
    if action_type == 0:
        port, max_len = ofp_dissector_v10.get_action(action_type, length,
                                                     payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('OUTPUT', 'green') + ' Length: ' + str(length) + ' Port: '\
            + colored(
                str('CONTROLLER(65533)' if port == 65533 else port),
                'green') + ' Max Length: ' + str(max_len)
    elif action_type == 1:
        vlan, pad = ofp_dissector_v10.get_action(action_type, length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetVLANID', 'green') + ' Length: ' + str(length) + \
            ' VLAN ID: ' + colored(str(vlan), 'green') + ' Pad: ' \
            + str(pad)
    elif action_type == 2:
        vlan_pc, pad = ofp_dissector_v10.get_action(action_type,
                                                    length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetVLANPCP', 'green') + ' Length: ' + str(length) + \
            ' VLAN PCP: ' + colored(str(vlan_pc), 'green') + ' Pad: ' \
            + str(pad)
    elif action_type == 3:
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('StripVLAN', 'green') + ' Length: ' + str(length)
    elif action_type == 4:
        setDLSrc, pad = ofp_dissector_v10.get_action(action_type,
                                                     length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetDLSrc', 'green') + ' Length: ' + str(length) + \
            ' SetDLSrc: ' + colored(str(eth_addr(setDLSrc)), 'green') + ' Pad: ' \
            + str(pad)
    elif action_type == 5:
        setDLDst, pad = ofp_dissector_v10.get_action(action_type,
                                                     length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetDLDst', 'green') + ' Length: ' + str(length) + \
            ' SetDLDst: ' + colored(str(eth_addr(setDLDst)), 'green') + ' Pad: ' \
            + str(pad)
    elif action_type == 6:
        nw_addr = ofp_dissector_v10.get_action(action_type,
                                               length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetNWSrc', 'green') + ' Length: ' + str(length) + \
            ' SetNWSrc: ' + colored(str(nw_addr), 'green')
    elif action_type == 7:
        nw_addr = ofp_dissector_v10.get_action(action_type,
                                               length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetNWDst', 'green') + ' Length: ' + str(length) + \
            ' SetNWDst: ' + colored(str(nw_addr), 'green')
    elif action_type == 8:
        nw_tos, pad = ofp_dissector_v10.get_action(action_type,
                                                   length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetNWTos' 'green') + ' Length: ' + str(length) + \
            ' SetNWTos: ' + colored(str(nw_tos), 'green') + ' Pad: ' \
            + str(pad)
    elif action_type == 9:
        port, pad = ofp_dissector_v10.get_action(action_type,
                                                 length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetTPSrc' 'green') + ' Length: ' + str(length) + \
            ' SetTPSrc: ' + colored(str(port), 'green') + ' Pad: ' \
            + str(pad)
    elif action_type == int('a', 16):
        port, pad = ofp_dissector_v10.get_action(action_type,
                                                 length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('SetTPDst' 'green') + ' Length: ' + str(length) + \
            ' SetTPDst: ' + colored(str(port), 'green') + ' Pad: ' \
            + str(pad)
    elif action_type == int('b', 16):
        port, pad, queue_id = ofp_dissector_v10.get_action(action_type,
                                                           length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('Enqueue', 'green') + ' Length: ' + str(length) + \
            ' Enqueue: ' + colored(str(port),  'green') + ' Pad: ' \
            + str(pad) + ' Queue: ' + str(queue_id)
    elif action_type == int('ffff', 16):
        vendor = ofp_dissector_v10.get_action(action_type,
                                              length, payload)
        print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + \
            colored('VENDOR', 'green') + ' Length: ' + str(length) + \
            ' Vendor: ' + colored(str(vendor),  'green')
    else:
        return 'Error'
