'''
    OpenFlow 1.3 prints
'''
import of13.dissector
import tcpiplib.prints


def red(string):
    return tcpiplib.prints.red(string)


def green(string):
    return tcpiplib.prints.green(string)


def datapath_id(string):
    return tcpiplib.prints.datapath_id(string)


def print_string(pkt):
    print pkt.of_body['print_string']['message']


def print_hello_elements(pkt):
    hello = pkt.of_body['print_hello_elements']
    print ('Hello - Element: %s Type: %s Length: %s' %
           (hello['count'], hello['type'], hello['length']))


def print_hello_bitmap(pkt):
    bitmaps = pkt.of_body['print_hello_bitmap']
    for bitmap in bitmaps:
        print ('Hello - Bitmap: %s' % (hex(bitmap)))


def print_of_error(pkt):
    codes = pkt.of_body['print_of_error']
    print ('OpenFlow Error - Type: %s Code: %s' %
           (red(codes['name']), red(codes['type'])))


def print_echoreq(pkt):
    print 'OpenFlow Echo Request'


def print_echores(pkt):
    print 'OpenFlow Echo Reply'


def print_of_feature_req(pkt):
    print 'OpenFlow Feature Request'


def print_of_feature_res(pkt):
    f_res = pkt.of_body['print_of_feature_res']
    print 'OpenFlow Feature Reply'
    dpid = datapath_id(f_res['datapath_id'])
    print ('FeatureRes - datapath_id: %s n_buffers: %s n_tbls: %s '
           'Auxiliary_ID: %s , pad: %s'
           % (green(dpid), f_res['n_buffers'], f_res['n_tbls'],
              f_res['auxiliary_id'], f_res['pad']))
    print ('FeatureRes - Capabilities:'),
    for i in f_res['caps']:
        print of13.dissector.get_feature_res_capabilities(i),
    print


def print_of_getconfig_req(pkt):
    print 'OpenFlow GetConfig Request'


def print_of_getConfigRes(pkt):
    configres = pkt.of_body['print_of_getConfigRes']
    print ('OpenFlow GetConfigRes - Flag: %s Miss_send_len: %s' %
           (configres['flag'], configres['miss']))


def print_of_setConfig(pkt):
    setconf = pkt.of_body['print_of_setConfig']
    print ('OpenFlow SetConfig - Flag: %s Miss_send_len: %s' %
           (setconf['flag'], setconf['miss']))


def print_flow_mod(pkt):
    fmod = pkt.of_body['print_flow_mod']
    string = ('FlowMod - Cookie/Mask: %s/%s Table_id: %s Command: %s '
              'Idle/Hard Timeouts: %s/%s\nFlowMod - Priority: %s '
              'Buffer ID: %s Out Port: %s Out Group: %s Flags: %s Pad: %s')

    command = green(of13.dissector.get_of_command(fmod['command']))
    flags = green(of13.dissector.get_of_flags(fmod['flags']))
    port = green(of13.dissector.get_phy_port_id(fmod['out_port']))
    print string % (fmod['cookie'], fmod['cookie_mask'],
                    fmod['table_id'], command, fmod['idle_timeout'],
                    fmod['hard_timeout'], fmod['priority'],
                    fmod['buffer_id'], port, fmod['out_group'],
                    flags, fmod['padding'])


def print_match_type(pkt):
    matches = pkt.of_body['print_match_type']
    print ('Flow Matches - Type: %s Length: %s' %
           (matches['type'], matches['length']))


def print_match(pkt):
    oxm_array = pkt.of_body['print_match']
    for oxm in oxm_array:
        print_match_generic(oxm)
        print_match_oxm(oxm)


def print_match_generic(oxm):
    print ('OXM Match: Class: %s Length: %s HasMask: %s Field: %s:' %
           (hex(oxm['class']), oxm['length'], oxm['hasmask'],
            green(of13.dissector.get_flow_match_fields(oxm['field'])))),


def print_match_oxm(oxm):
    if oxm['hasmask'] == 0:
        if oxm['field'] in [0]:
            oxm['value'] = oxm['value'] & 0xffff
            oxm['value'] = of13.dissector.get_phy_port_id(oxm['value'])
        # DL_DST or DL_SRC
        elif oxm['field'] in [3, 4, 24, 25, 32, 33]:
            print green(tcpiplib.prints.eth_addr(oxm['value']))
            return
        # DL_TYPE
        elif oxm['field'] in [5]:
            oxm['value'] = hex(oxm['value'])
        # DL_VLAN
        elif oxm['field'] == 6:
            if oxm['value'] == 0:
                oxm['value'] = 'UNTAGGED'
            else:
                oxm['value'] = oxm['value'] & 0xfff
        # NW_SRC or NW_DST
        elif oxm['field'] in [11, 12, 22, 23]:
            oxm['value'] = tcpiplib.prints.get_ip_from_long(oxm['value'])
        # IPv6 Extensions
        elif oxm['field'] in [39]:
            extensions = of13.parser.parse_ipv6_extension_header(oxm['values'])
            for i in extensions:
                print green(of13.dissector.get_ipv6_extension(i)),

        print '%s' % green(oxm['value'])

    elif oxm['hasmask'] == 1:
        if oxm['field'] in [3, 4, 24, 25]:
            oxm['value'] = tcpiplib.prints.eth_addr(oxm['value'])
            oxm['mask'] = tcpiplib.prints.eth_addr(oxm['mask'])
        if oxm['field'] in [11, 12, 22, 23]:
            oxm['value'] = tcpiplib.prints.get_ip_from_long(oxm['value'])
            oxm['mask'] = tcpiplib.prints.get_ip_from_long(oxm['mask'])

        print ('%s/%s' % (green(oxm['value']), green(oxm['mask'])))


def print_padding(pkt):
    padding = pkt.of_body['print_padding']
    if padding['message'] is 0:
        print ('Padding: 0')
    else:
        print ('Padding: '),
        for i in range(0, padding['message']):
            print '\b0',
        print


def print_instruction(pkt):
    print ('Instructions:'),


def print_of_BarrierReq(pkt):
    print 'OpenFlow Barrier Request'


def print_of_BarrierReply(pkt):
    print 'OpenFlow Barrier Reply'


def print_body(pkt):
    for f in pkt.printing_seq:
        eval(f)(pkt)
