'''
    OpenFlow 1.3 prints
'''
import gen.prints
import of13.dissector


def red(string):
    return gen.prints.red(string)


def green(string):
    return gen.prints.green(string)


def datapath_id(string):
    return gen.prints.datapath_id(string)


def print_hello_elememnts(of_xid, el_type, el_length, count):
    print ('%s Hello - Element: %s Type: %s Length: %s' %
           (of_xid, count, el_type, el_length))


def print_hello_bitmap(of_xid, bitmap):
    print ('%s Hello - Bitmap: %s' % (of_xid, hex(bitmap)))


def print_of_error(of_xid, nameCode, typeCode):
    print ('%s OpenFlow Error - Type: %s Code: %s' %
           (of_xid, red(nameCode), red(typeCode)))


def print_echoreq(of_xid):
    print ('%s OpenFlow Echo Request' % (of_xid))


def print_echores(of_xid):
    print ('%s OpenFlow Echo Reply' % (of_xid))


def print_of_feature_req(of_xid):
    print '%s OpenFlow Feature Request' % of_xid


def print_of_feature_res(of_xid, f_res):
    print '%s OpenFlow Feature Reply' % of_xid
    dpid = datapath_id(f_res['datapath_id'])
    print ('%s FeatureRes - datapath_id: %s n_buffers: %s n_tbls: %s '
           'Auxiliary_ID: %s , pad: %s'
           % (of_xid, green(dpid), f_res['n_buffers'], f_res['n_tbls'],
              f_res['auxiliary_id'], f_res['pad']))
    print ('%s FeatureRes - Capabilities:' % of_xid),
    for i in f_res['caps']:
        print of13.dissector.get_feature_res_capabilities(i),
    print


def print_of_getconfig_req(of_xid):
    print '%s OpenFlow GetConfig Request' % of_xid


def print_of_getConfigRes(of_xid, flag, miss):
    print ('%s OpenFlow GetConfigRes - Flag: %s Miss_send_len: %s' %
           (of_xid, flag, miss))


def print_of_setConfig(of_xid, flag, miss):
    print ('%s OpenFlow SetConfig - Flag: %s Miss_send_len: %s' %
           (of_xid, flag, miss))


def print_flow_mod(of_xid, fmod):
    string = ('%s FlowMod - Cookie/Mask: %s/%s Table_id: %s Command: %s '
              'Idle/Hard Timeouts: %s/%s\n%s FlowMod - Priority: %s '
              'Buffer ID: %s Out Port: %s Out Group: %s Flags: %s Pad: %s')

    command = green(of13.dissector.get_of_command(fmod['command']))
    flags = green(of13.dissector.get_of_flags(fmod['flags']))
    port = green(of13.dissector.get_phy_port_id(fmod['out_port']))
    print string % (of_xid, fmod['cookie'], fmod['cookie_mask'],
                    fmod['table_id'], command, fmod['idle_timeout'],
                    fmod['hard_timeout'], of_xid, fmod['priority'],
                    fmod['buffer_id'], port, fmod['out_group'],
                    flags, fmod['padding'])


def print_match_type(of_xid, m_type, m_length):
    print '%s Flow Matches - Type: %s Length: %s' % (of_xid, m_type, m_length)


def print_match_generic(of_xid, oxm):
    print ('%s OXM Match: Class: %s Length: %s HasMask: %s Field: %s:' %
           (of_xid, hex(oxm['class']), oxm['length'], oxm['hasmask'],
            green(of13.dissector.get_flow_match_fields(oxm['field'])))),


def print_match(oxm):
    if oxm['hasmask'] == 0:
        if oxm['field'] in [0]:
            oxm['value'] = oxm['value'] & 0xffff
            oxm['value'] = of13.dissector.get_phy_port_id(oxm['value'])
        # DL_DST or DL_SRC
        elif oxm['field'] in [3, 4, 24, 25, 32, 33]:
            print green(gen.prints.eth_addr(oxm['value']))
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
            oxm['value'] = gen.prints.get_ip_from_long(oxm['value'])
        # IPv6 Extensions
        elif oxm['field'] in [39]:
            extensions = of13.parser.parse_ipv6_extension_header(oxm['values'])
            for i in extensions:
                print green(of13.dissector.get_ipv6_extension(i)),

        print '%s' % green(oxm['value'])

    elif oxm['hasmask'] == 1:
        if oxm['field'] in [3, 4, 24, 25]:
            oxm['value'] = gen.prints.eth_addr(oxm['value'])
            oxm['mask'] = gen.prints.eth_addr(oxm['mask'])
        if oxm['field'] in [11, 12, 22, 23]:
            oxm['value'] = gen.prints.get_ip_from_long(oxm['value'])
            oxm['mask'] = gen.prints.get_ip_from_long(oxm['mask'])

        print ('%s/%s' % (green(oxm['value']), green(oxm['mask'])))


def print_of_BarrierReq(of_xid):
    print '%s OpenFlow Barrier Request' % of_xid


def print_of_BarrierReply(of_xid):
    print '%s OpenFlow Barrier Reply' % of_xid
