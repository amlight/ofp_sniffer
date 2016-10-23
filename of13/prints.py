"""
    OpenFlow 1.3 prints
"""
from hexdump import hexdump
import of13.dissector
import tcpiplib.prints
from gen.prints import red, green


def print_pad(pad):
    """
        Used to print pads as a sequence of 0s: 0, 00, 000..
        Args:
            pad: pad in str format
        Returns: string with '0'
    """
    pad_len = len(pad)
    string = '0'
    if pad_len == 1:
        return '0'
    for item in range(0, pad_len-1):
        string += '0'
    return string


# ################## OFPT_HELLO ############################


def print_hello(msg):
    count = 0
    for element in msg.elements:
        count += 1
        print ("Hello - Element: %s Type: %s Length: %s" %
               (count, element.type, element.length))
        count_bit = 0
        for bitmap in element.versiobitmap:
            count_bit += 1
            print ("Hello - Bitmap: %s Type: %s Length: %s" %
                   (count_bit, bitmap.type, bitmap.length))
            print 'Bitmap: %08d' % int(bitmap.bitmaps.split('b')[1])


# ################## OFPT_ERROR ############################


def print_error_msg(msg):
    print ("Error - Type: %s Code: %s" % (msg.error_type, msg.code))
    if len(msg.data):
        print hexdump(msg.data)
    return 0


# ################## OFPT_ECHO_REQUEST ############################


def print_echo_request(msg):
    print "Echo - Data: %s" % msg.data
    return 0


# ################## OFPT_ECHO_REPLY ############################


def ofp_echo_reply(msg):
    print "Echo - Data: %s" % msg.data
    return 0


# ################## OFPT_EXPERIMENTER ############################


def print_experimenter(msg):
    return 0


# ################## OFPT_FEATURE_REQUEST ############################


def print_switch_features(msg):
    print "OpenFlow Switch Features:"
    print ("Datapath_id: %s N_Buffers: %s N_Tbls: %s\nAuxiliary_id: %s "
           "Pad: %s Reserved: %s" %
           (red(tcpiplib.prints.datapath_id(msg.datapath_id)),
            msg.n_buffers,  msg.n_tbls, msg.auxiliary_id,
            print_pad(msg.pad), green(msg.reserved)))
    print ("Capabilities: "),
    for i in msg.caps:
        print of13.dissector.get_feature_res_capabilities(i),
    print

# ########## OFPT_GET_CONFIG_REPLY & OFPT_SET_CONFIG ###############


def print_switch_config(msg):
    print ('Switch Configuration - Flag: %s Miss_Send_Len: %s' %
           (msg.flag, msg.miss_send_len))
    return 0


# ################## OFPT_PACKET_IN ############################


def print_packet_in(msg):
    return 0


# ################## OFPT_FLOW_REMOVED ############################


def print_flow_removed(msg):
    return 0


# ################## OFPT_PORT_STATUS ############################


def print_port_status(msg):
    return 0


# ################## OFPT_PACKET_OUT ############################


def print_packet_out(msg):
    return 0


# ################## OFPT_FLOW_MOD ############################


def print_flow_mod(msg):
    # Print main flow_mod options
    string = ('FlowMod - Cookie/Mask: %s/%s Table_id: %s Command: %s '
              'Idle/Hard Timeouts: %s/%s\nFlowMod - Priority: %s '
              'Buffer ID: %s Out Port: %s Out Group: %s Flags: %s Pad: %s')

    command = green(of13.dissector.get_flow_mod_command(msg.command))
    flags = green(of13.dissector.get_flow_mod_flags(msg.flags))
    port = green(of13.dissector.get_phy_port_id(msg.out_port))
    print string % (msg.cookie, msg.cookie_mask,
                    msg.table_id, command, msg.idle_timeout,
                    msg.hard_timeout, msg.priority,
                    msg.buffer_id, port, msg.out_group,
                    flags, print_pad(msg.pad))

    # Print print_match_type(msg)
    print_match_type(msg.match)
    print_instruction(msg.instructions)


def print_match_type(match):
    print ('Flow Matches - Type: %s Length: %s' % (match.type, match.length))
    # print oxm_fields
    print_match_oxm_fields(match.oxm_fields)


def print_match_oxm_fields(oxm_fields):
    for oxm in oxm_fields:
        print_match_generic(oxm)
        print_match_oxm(oxm)


def print_match_generic(oxm):
    print (' OXM Match: Class: %s Length: %s HasMask: %s Field: %s:' %
           (hex(oxm.oxm_class), oxm.length, oxm.hasmask,
            green(of13.dissector.get_flow_match_fields(oxm.field)))),


def print_match_oxm(oxm):
    if oxm.hasmask == 0:
        if oxm.field in [0]:
            oxm.payload.value = oxm.payload.value & 0xffff
            oxm.payload.value = of13.dissector.get_phy_port_id(oxm.payload.value)
        # DL_DST or DL_SRC
        elif oxm.field in [3, 4, 24, 25, 32, 33]:
            print green(tcpiplib.prints.eth_addr(oxm.payload.value))
            return
        # DL_TYPE
        elif oxm.field in [5]:
            oxm.payload.value = hex(oxm.payload.value)
        # DL_VLAN
        elif oxm.field == 6:
            if oxm.payload.value == 0:
                oxm.payload.value = 'UNTAGGED'
            else:
                oxm.payload.value = oxm.payload.value & 0xfff
        # NW_SRC or NW_DST
        elif oxm.field in [11, 12, 22, 23]:
            oxm.payload.value = tcpiplib.prints.get_ip_from_long(oxm.payload.value)
        # IPv6 Extensions
        elif oxm.field in [39]:
            extensions = of13.parser.parse_ipv6_extension_header(oxm.payload.values)
            for i in extensions:
                print green(of13.dissector.get_ipv6_extension(i)),

        print '%s' % green(oxm.payload.value)

    elif oxm.hasmask == 1:
        if oxm.field in [3, 4, 24, 25]:
            oxm.payload.value = tcpiplib.prints.eth_addr(oxm.payload.value)
            oxm.payload.mask = tcpiplib.prints.eth_addr(oxm.payload.mask)
        if oxm.field in [11, 12, 22, 23]:
            oxm.payload.value = tcpiplib.prints.get_ip_from_long(oxm.payload.value)
            oxm.payload.mask = tcpiplib.prints.get_ip_from_long(oxm.payload.mask)

        print ('%s/%s' % (green(oxm.payload.value), green(oxm.payload.mask)))


def print_instruction(instructions):
    print ('Flow Instructions:')
    for instruction in instructions:
        print ' Instruction: Type %s Length: %s' %\
              (instruction.type, instruction.length)
        for action in instruction.actions:
            print ('  Action - Type %s Length %s' % (action.type, action.length)),
            if action.type == 0:
                print ("Port %s Max_Len %s Pad %s" %
                       (action.port, action.max_len, print_pad(action.pad)))
            if action.type == 1:
                print ("VLAN_VID %s Pad %s" %
                       (action.vlan_vid, print_pad(action.pad)))


# ################## OFPT_GROUP_MOD ############################


def print_group_mod(msg):
    return 0


# ################## OFPT_PORT_MOD ############################


def print_port_mod(msg):
    return 0


# ################## OFPT_TABLE_MOD ############################


def print_table_mod(msg):
    return 0


# ################## OFPT_MULTIPART_REQUEST ############################


def print_multipart_request(msg):
    return 0


# ################## OFPT_MULTIPART_REPLY ############################


def print_multipart_reply(msg):
    return 0


# ################## OFPT_QUEUE_GET_CONFIG_REQUEST ############################


def print_queue_get_config_request(msg):
    return 0


# ################## OFPT_QUEUE_GET_CONFIG_REPLY ############################


def print_queue_get_config_reply(msg):
    return 0


# ########## OFPT_ROLE_REQUEST & OFPT_ROLE_REPLY ###############


def print_role(msg):
    return 0


# ########### OFPT_GET_ASYNC_REPLY & OFPT_SET_ASYNC #####################


def print_async_config(msg):
    return 0


# ################## OFPT_METER_MOD ############################


def print_meter_mod(msg):
    return 0

