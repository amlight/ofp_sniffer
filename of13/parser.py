"""
    Parser of the OpenFlow 1.3 message
"""
import netaddr
from struct import unpack
import of13.packet
import of13.dissector
from pyof.v0x04.common.utils import unpack_message


# ################## OFPT_HELLO ############################


# def parse_hello(msg, packet):
#
#     start = 0
#     elements = []
#
#     # Get all Elements
#     # Each Element has 0 - N bitmaps
#     while len(packet[start:]) > 0:
#         # Get element[]
#         elem = unpack('!HH', packet[start:start+4])
#         element = of13.packet.ofp_hello.ofp_hello_elem_header()
#         element.type = elem[0]
#         element.length = elem[1]
#
#         bitmaps_list = []
#         bitmaps = packet[start+4:start+element.length]
#         start_bit = 0
#         while len(bitmaps[start_bit:]) > 0:
#             bp = unpack('!HH', packet[start_bit:start_bit+4])
#             bitmap = of13.packet.ofp_hello.ofp_hello_elem_versionbitmap()
#             bitmap.type = bp[0]
#             bitmap.length = bp[1]
#
#             bmp = unpack('!L', packet[start_bit+4:])
#             bitmap.bitmaps = bmp[0]
#
#             start_bit = start_bit + 4 + bitmap.bitmaps
#
#             bitmap.bitmaps = bin(bitmap.bitmaps)
#
#             bitmaps_list.append(bitmap)
#             del bitmap
#
#         element.versiobitmap = bitmaps_list
#         start += element.length
#
#         elements.append(element)
#
#         del element
#
#     msg.elements = elements
#     return 1

def parse_hello(msg, packet):
    try:
        print('parse_hello')
        data = unpack_message(packet)
        print('err')
        print(data)
    except Exception as err:
        print(err)


# ################## OFPT_ERROR ############################


def parse_error_msg(msg, packet):
    of_error = packet[0:4]
    ofe = unpack('!HH', of_error)
    ofe_type = ofe[0]
    ofe_code = ofe[1]

    msg.error_type, msg.code = of13.dissector.get_ofp_error(ofe_type, ofe_code)
    return 1


# ################## OFPT_ECHO_REQUEST ############################


def parse_echo_request(msg, packet):
    length = len(packet)
    strg = '!%ss' % length
    msg.data = unpack(strg, packet)

    return 0


# ################## OFPT_ECHO_REPLY ############################


def parse_echo_reply(msg, packet):
    length = len(packet)
    strg = '!%ss' % length
    msg.data = unpack(strg, packet)
    return 0


# ################## OFPT_EXPERIMENTER ############################


def parse_experimenter(msg, packet):
    msg.experimenter = 'To finish this function' + packet
    return 0


# ################## OFPT_FEATURE_REPLY ############################


def _parse_bitmask(bitmask, array):
    size = len(array)
    for i in range(0, size):
        mask = 2**i
        aux = bitmask & mask
        if aux == 0:
            array.remove(mask)
    return array


def _parse_capabilities(capabilities):
    caps = [1, 2, 4, 8, 16, 32, 64, 128, 256]
    return _parse_bitmask(capabilities, caps)


def parse_switch_features(msg, packet):
    of_fres = packet[0:24]
    ofrs = unpack('!8sLBB2sLL', of_fres)
    caps = _parse_capabilities(ofrs[5])

    msg.datapath_id = ofrs[0]
    msg.n_buffers = ofrs[1]
    msg.n_tbls = ofrs[2]
    msg.auxiliary_id = ofrs[3]
    msg.pad = ofrs[4]
    msg.caps = caps
    msg.reserved = ofrs[6]

    return 1


# ########## OFPT_GET_CONFIG_REPLY & OFPT_SET_CONFIG ###############


def parse_switch_config(msg, packet):
    options = unpack('!HH', packet[:4])
    msg.flag = of13.dissector.get_config_flags(options[0])
    msg.miss_send_len = options[1]

    return 1


# ################## OFPT_PACKET_IN ############################


def parse_packet_in(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_FLOW_REMOVED ############################


def parse_flow_removed(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_PORT_STATUS ############################


def parse_port_status(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_PACKET_OUT ############################


def parse_packet_out(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_FLOW_MOD ############################


# def parse_ipv6_extension_header(extensions):
    # still useful?
#    bits = [1, 2, 4, 8, 16, 32, 64, 128, 256]
#    return _parse_bitmask(extensions, bits)

def _parse_action_output(packet, start, a_type, a_length, offset=12):
    # Output has 12 bytes
    raw2 = unpack('!LH6s', packet[start:start + offset])
    action = of13.packet.ofp_action_set_output(a_type, a_length)
    action.port = raw2[0]
    action.max_len = raw2[1]
    action.pad = raw2[2]
    return action, offset


def _parser_action_set_vlan_vid(packet, start, a_type, a_length, offset=4):
    # Set_vlan_vid has 4 bytes
    raw2 = unpack('!H2s', packet[start:start + offset])
    action = of13.packet.ofp_action_set_vlan_vid(a_type, a_length)
    action.vlan_vid = raw2[0]
    action.pad = raw2[1]
    return action, offset


def _parse_actions(packet):

    actions = []
    start = 0

    while len(packet[start:]) > 0:
        raw = unpack('!HH', packet[start:start + 4])
        action_type = raw[0]
        action_length = raw[1]

        start += 4

        action_types = {0: _parse_action_output, 1: _parser_action_set_vlan_vid}

        try:
            action, offset = action_types[action_type](packet, start, action_type, action_length)
        except KeyError:
            return 0

        actions.append(action)
        start += offset

    return actions


def _inst_goto_table(packet, start, instruction):
    raw = unpack('!B3s', packet[start:start+4])
    instruction.table_id = raw[0]
    instruction.pad = raw[1]


def _inst_write_metadata(packet, start, instruction):
    raw = unpack('!4s12s12s', packet[start:start + 28])
    instruction.pad = raw[0]
    instruction.metadata = raw[1]
    instruction.metadata_mask = raw[2]


def _inst_write_apply_clear_actions(packet, instruction):

    raw = unpack('!4s', packet[:4])
    instruction.pad = raw[0]
    instruction.actions = _parse_actions(packet[4:])


def _inst_meter(packet, start, instruction):
    raw = unpack('!L', packet[start:start + 4])
    instruction.meter_id = raw[0]


def _inst_experimenter(packet, start, instruction):
    raw = unpack('!L', packet[start:start + 4])
    instruction.experimenter_id = raw[0]


def _parse_instructions(packet, start):

    instructions = []

    while len(packet[start:]) > 0:

        instruction = unpack('!HH', packet[start:start+4])
        i_type = instruction[0]
        i_len = instruction[1]

        # Call proper instruction
        if i_type == 1:
            instruction = of13.packet.ofp_instruction_go_to(i_type, i_len)
            _inst_goto_table(packet, start, instruction)
        elif i_type == 2:
            instruction = of13.packet.ofp_instruction_write_metadata(i_type, i_len)
            _inst_write_metadata(packet, start, instruction)
        elif i_type in [3, 4, 5]:
            instruction = of13.packet.ofp_instruction_wac_actions(i_type, i_len)
            _inst_write_apply_clear_actions(packet[start + 4:], instruction)
        elif i_type == 6:
            instruction = of13.packet.ofp_instruction_meter(i_type, i_len)
            _inst_meter(packet, start, instruction)
        else:
            instruction = of13.packet.ofp_instruction_experimenter(i_type, i_len)
            _inst_experimenter(packet, start, instruction)

        instructions.append(instruction)
        del instruction
        start = start + i_len

    return instructions


def unpack_oxm_payload(oxm_tlv, packet_oxm_payload):

    payload = of13.packet.ofp_match_oxm_payload()
    len_packet_oxm_content = len(packet_oxm_payload)
    strg = ''

    if oxm_tlv.hasmask == 0:
        if len_packet_oxm_content == 1:
            strg = '!B'
        elif len_packet_oxm_content == 2:
            strg = '!H'
        elif len_packet_oxm_content == 3:
            strg = '!3s'
        elif len_packet_oxm_content == 4:
            strg = '!L'
        elif len_packet_oxm_content == 6:
            strg = '!6s'
        elif len_packet_oxm_content == 8:
            strg = '!Q'
        elif len_packet_oxm_content == 16:
            net, host = unpack('!QQ', packet_oxm_payload)
            ipv6 = ((net << 64) | host)
            payload.value = netaddr.IPAddress(ipv6)

            return payload

        payload.value = unpack(strg, packet_oxm_payload)[0]

    else:
        if len_packet_oxm_content == 2:
            strg = '!BB'
        elif len_packet_oxm_content == 4:
            strg = '!HH'
        elif len_packet_oxm_content == 6:
            strg = '!3s3s'
        elif len_packet_oxm_content == 8:
            strg = '!LL'
        elif len_packet_oxm_content == 12:
            strg = '!6s6s'
        elif len_packet_oxm_content == 16:
            strg = '!QQ'
        elif len_packet_oxm_content == 32:
            net, host, net1, host1 = unpack('!QQQQ', packet_oxm_payload)
            host = (net << 64) | host
            subnet = (net1 << 64) | host1
            payload.value = netaddr.IPAddress(host)
            payload.mask = netaddr.IPAddress(subnet)

            return payload

        payload.value, payload.mask = unpack(strg, packet_oxm_payload)

    return payload


def _parse_matches(match, packet, start):

    match.type, match.length = unpack('!HH', packet[start:start + 4])

    length_oxm = match.length - 4
    match.pad = (match.length + 7)/8*8 - match.length

    start += 4
    oxms = packet[start:start+length_oxm]

    start_2 = 0
    oxm_array = []
    while len(oxms[start_2:]) > 0:
        oxm_raw = unpack('!L', oxms[start_2:start_2 + 4])

        oxm_tlv = of13.packet.ofp_match_oxm_fields()
        oxm_tlv.oxm_class = (oxm_raw[0] >> 16)
        oxm_tlv.field = ((oxm_raw[0] >> 9) & 0x7f)
        oxm_tlv.hasmask = ((oxm_raw[0] >> 8) & 1)
        oxm_tlv.length = (oxm_raw[0] & 0xff)

        packet_oxm_payload = oxms[start_2+4:start_2 + 4 + oxm_tlv.length]

        oxm_tlv.payload = unpack_oxm_payload(oxm_tlv, packet_oxm_payload)

        oxm_array.append(oxm_tlv)

        start_2 = start_2 + 4 + oxm_tlv.length

        del oxm_tlv

    match.oxm_fields = oxm_array

    # Return offset for Instructions
    return start + length_oxm + match.pad


def parse_flow_mod(msg, packet):

    ofmod = unpack('!QQBBHHHLLLH2s', packet[:40])

    cookie = ofmod[0] if ofmod[0] > 0 else 0
    cookie_mask = ofmod[1] if ofmod[1] > 0 else 0

    msg.cookie = '0x' + format(cookie, '02x')
    msg.cookie_mask = '0x' + format(cookie_mask, '02x')
    msg.buffer_id = '0x' + format(ofmod[7], '02x')
    msg.out_port = 4294967040 if ofmod[8] > 4294967040 else ofmod[8]
    msg.table_id = ofmod[2]
    msg.command = ofmod[3]
    msg.idle_timeout = ofmod[4]
    msg.hard_timeout = ofmod[5]
    msg.priority = ofmod[6]
    msg.out_group = ofmod[9]
    msg.flags = ofmod[10]
    msg.pad = ofmod[11]

    instructions_start = _parse_matches(msg.match, packet, 40)

    msg.instructions = _parse_instructions(packet, instructions_start)

    return 1


# ################## OFPT_GROUP_MOD ############################


def parse_group_mod(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_PORT_MOD ############################


def parse_port_mod(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_TABLE_MOD ############################


def parse_table_mod(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_MULTIPART_REQUEST ############################


def parse_multipart_request(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_MULTIPART_REPLY ############################


def parse_multipart_reply(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_QUEUE_GET_CONFIG_REQUEST ############################


def parse_queue_get_config_request(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_QUEUE_GET_CONFIG_REPLY ############################


def parse_queue_get_config_reply(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ########## OFPT_ROLE_REQUEST & OFPT_ROLE_REPLY ###############


def parse_role(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ########### OFPT_GET_ASYNC_REPLY & OFPT_SET_ASYNC #####################


def parse_async_config(msg, packet):
    msg.data = 'To finish' + packet
    return 0


# ################## OFPT_METER_MOD ############################


def parse_meter_mod(msg, packet):
    msg.data = 'To finish' + packet
    return 0
