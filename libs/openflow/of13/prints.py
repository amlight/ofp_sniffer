"""
    OpenFlow 1.3 prints
"""
from struct import unpack
from hexdump import hexdump
from pyof.foundation.basic_types import BinaryData
import libs.tcpiplib.prints
from libs.gen.prints import red, green
from libs.openflow import of13
import libs.openflow.of13.dissector as dissector
from libs.tcpiplib.process_data import dissect_data


def prints_ofp(msg):
    """

    Args:
        msg: OpenFlow 1.3 message unpacked by python-openflow
    Returns:

    """

    try:
        msg_types = {0: print_ofpt_hello,  # ok
                     1: print_ofpt_error,  # ok
                     2: print_ofpt_echo_request,  # ok
                     3: print_ofpt_echo_reply,  # ok
                     4: print_ofpt_experimenter,  # pending
                     5: print_ofpt_features_request,  # ok
                     6: print_ofpt_features_reply,  # ok
                     7: print_ofpt_get_config_request,  # ok
                     8: print_ofpt_get_config_reply,  # ok
                     9: print_ofpt_set_config,  # ok
                     10: print_ofpt_packet_in,  # ok
                     11: print_ofpt_flow_removed,  # ok
                     12: print_ofpt_port_status,  # ok
                     13: print_ofpt_packet_out,  # pending
                     14: print_ofpt_flow_mod,  # ok?
                     15: print_ofpt_group_mod,
                     16: print_ofpt_port_mod,  # pending
                     17: print_ofpt_table_mod,
                     18: print_ofpt_multipart_request,
                     19: print_ofpt_multipart_reply,
                     20: print_ofpt_barrier_request,
                     21: print_ofpt_barrier_reply,
                     22: print_ofpt_queue_get_config_request,
                     23: print_ofpt_queue_get_config_reply,
                     24: print_ofpt_role_request,
                     25: print_ofpt_role_reply,
                     26: print_ofpt_get_async_request,
                     27: print_ofpt_get_async_reply,
                     28: print_ofpt_set_async,
                     29: print_ofpt_meter_mod
                     }

        return msg_types[msg.header.message_type.value](msg)
    except Exception as err:
        print("Error: %s" % err)


def print_pad(pad):
    """
        Used to print pads as a sequence of 0s: 0, 00, 000..
        Args:
            pad: pad in int format
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


def get_of_versions_support(bitmap):
    count = 0
    versions = list()
    for bit in bitmap[::-1]:
        if count == 1 and bit == '1':
            versions.append("OpenFlow 1.0")
        if count == 2 and bit == '1':
            versions.append("OpenFlow 1.1")
        if count == 3 and bit == '1':
            versions.append("OpenFlow 1.2")
        if count == 4 and bit == '1':
            versions.append("OpenFlow 1.3")
        if count == 5 and bit == '1':
            versions.append("OpenFlow 1.4")
        if count == 6 and bit == '1':
            versions.append("OpenFlow 1.5")
        count = count + 1
    return ' '.join(versions)


def print_element_payload(bitmap):
    """ Print ofp_hello_elem_versionbitmap
    Args:
        bitmap: bitmaps entry
    """
    bits = bin(int.from_bytes(bitmap, byteorder='big', signed=False))
    bitmap = bits.replace('b', '0')
    versions = get_of_versions_support(bitmap)
    print('Bitmap: %s (%s)' % (bitmap, versions))


def print_ofp_hello_elem_header(count, element):
    """ Print OFP_HELLO_ELEM_HEADER
    Args:
        count: element counter
        element: element msg
    """
    print("Element #: %s Type: %s Length: %s" %
          (count,
           dissector.get_ofp_hello_elem_type(element.element_type.value),
           element.length))

    if len(element.length) == 4:
        # That means there is/are no bitmap(s)
        return

    # In theory, it would be an array but there won't be
    # more than 31 OpenFlow versions. In this case, we
    # consider just one bitmaps entry
    if element.element_type.value == 1:
        print_element_payload(element.content.value)


def print_ofpt_hello(msg):
    """ Header already printed. If elements are included, let's
    process then.
    Args:
        msg: Hello Msg
    """
    if msg.header.length > 0:
        count = 0
        for element in msg.elements:
            count += 1
            print_ofp_hello_elem_header(count, element)


# ################## OFPT_ERROR ############################


def print_ofpt_error(msg):
    print("Error - Type: %s Code: %s" % (msg.error_type, msg.code))
    if len(msg.data):
        print(hexdump(msg.data))
    return 0


# ################## OFPT_ECHO_REQUEST ############################


def print_ofpt_echo_request(msg):
    if not isinstance(msg.data, BinaryData) and len(msg.data) > 0:
        print("Echo Request - Data: %s" % hexdump(msg.data))
    elif isinstance(msg.data, BinaryData):
        print("Echo Reply - Data: \"%s\"" % msg.data.value.decode("utf-8"))
    return 0


# ################## OFPT_ECHO_REPLY ############################


def print_ofpt_echo_reply(msg):
    if not isinstance(msg.data, BinaryData) and len(msg.data) > 0:
        print("Echo Reply - Data: %s" % hexdump(msg.data))
    elif isinstance(msg.data, BinaryData):
        print("Echo Reply - Data: \"%s\"" % msg.data.value.decode("utf-8"))
    return 0


# ################## OFPT_EXPERIMENTER ############################


def print_ofpt_experimenter(msg):
    return 0


# ################## OFPT_FEATURE_REQUEST ############################


def print_ofpt_features_request(msg):
    return 0


# ################## OFPT_FEATURE_REPLY ############################


def parse_bitmask(bitmask, array):
    size = len(array)
    for i in range(0, size):
        mask = 2**i
        aux = bitmask & mask
        if aux == 0:
            try:
                array.remove(mask)
            except ValueError:
                pass
    return array


def parse_capabilities(capabilities):
    caps = [1, 2, 4, 8, 32, 64, 256]
    return parse_bitmask(capabilities, caps)


def print_ofpt_features_reply(msg):
    print("Datapath_id: %s N_Buffers: %s N_Tables: %s "
          "Auxiliary_id: %s Pad: %s Reserved: %s" %
          (red(msg.datapath_id),
           msg.n_buffers, red(msg.n_tables), msg.auxiliary_id,
           msg.pad, msg.reserved))
    print("Capabilities: ", end="")
    caps = parse_capabilities(msg.capabilities)
    for i in caps:
        print(libs.openflow.of13.dissector.get_feature_res_capabilities(i), end=" "),
    print()


# ################## OFPT_GET_CONFIG_REQUEST ###################


def print_ofpt_get_config_request(msg):
    return 0


# ################## OFPT_GET_CONFIG_REPLY ###################


def print_ofpt_get_config_reply(msg):
    print('Switch Configuration - Flag: %s Miss_Send_Len: %s' %
          (msg.flags, msg.miss_send_len))
    return 0


# ################## OFPT_SET_CONFIG #########################


def print_ofpt_set_config(msg):
    print('Switch Configuration - Flags: %s Miss_Send_Len: %s' %
          (dissector.get_config_flags(msg.flags.value), msg.miss_send_len))
    return 0


# ################## OFPT_PACKET_IN ############################


def print_ofpt_packet_in(msg):
    """
    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    print('PacketIn: buffer_id: %s total_len: %s reason: %s table_id: %s '
          'cookie: %s ' %
          (hex(msg.buffer_id.value), msg.total_len.value,
           green(dissector.get_packet_in_reason(msg.reason.value)),
           green(msg.table_id.value), msg.cookie.value))
    print('Match: ', end='')
    print_match_type(msg.match)
    print('Pad: %s' % msg.pad)
    print_data(msg.data)


def print_data(data):
    """
        Print msg.data from both PacketIn and PacketOut
        Args:
            data: msg.data - array of protocols
    """
    if isinstance(data, BinaryData):
        data = dissect_data(data)

    if isinstance(data, int):
        print("OpenFlow message has no data")
        return

    try:
        eth = data.pop(0)
        libs.tcpiplib.prints.print_layer2(eth)
        next_protocol = eth.protocol

        if next_protocol in [33024]:
            vlan = data.pop(0)
            libs.tcpiplib.prints.print_vlan(vlan)
            next_protocol = vlan.protocol

        if next_protocol in [35020, 35138]:
            lldp = data.pop(0)
            libs.tcpiplib.prints.print_lldp(lldp)
        elif next_protocol in [34998]:
            fvd = data.pop(0)
            libs.tcpiplib.prints.print_oessfvd(fvd)
        elif next_protocol in [2048]:
            ip = data.pop(0)
            libs.tcpiplib.prints.print_layer3(ip)
            if ip.protocol is 6:
                tcp = data.pop(0)
                libs.tcpiplib.prints.print_tcp(tcp)
        elif next_protocol in [2054]:
            arp = data.pop(0)
            libs.tcpiplib.prints.print_arp(arp)
    except Exception as error:
        print("ERROR: %s" % error)


# ################## OFPT_FLOW_REMOVED ############################


def print_ofpt_flow_removed(msg):
    """
        Args:
            msg: OpenFlow message unpacked by python-openflow
    """

    # Print main flow_removed options
    string = ('Body - Cookie: %s Priority: %s Reason: %s table_id: %s\nBody - '
              'Duration Secs/NSecs: %s/%s Idle Timeout: %s Hard Timeout: %s'
              ' Packet Count: %s Byte Count: %s')

    print(string % (msg.cookie, msg.priority, red(msg.reason),
                    msg.table_id, msg.duration_sec, msg.duration_nsec,
                    msg.idle_timeout, msg.hard_timeout,
                    msg.packet_count, msg.byte_count))

    print_match_type(msg.match)


# ################## OFPT_PORT_STATUS ############################


def print_ofpt_port_status(msg):
    """
        Args:
            msg: OpenFlow message unpacked by python-openflow | page 113
    """
    print('OpenFlow PortStatus - Reason: %s Pad: %s' %
          (msg.reason, msg.pad))
    print_of_ports(msg.desc) # TODO: print_of_ports in part of "Multipurpose port functions" in 1.0. Can I use those functions here?

    return 0


# ################## OFPT_PACKET_OUT ############################


def print_ofpt_packet_out(msg):
    """
        Args:
            msg: OpenFlow message unpacked by python-openflow  ; PAGE 107 MANUAL
    """
    print('PacketOut: buffer_id: %s in_port: %s actions_len: %s' %
          (hex(msg.buffer_id.value),
           green(dissector.get_phy_port_id(msg.in_port.value)),
           msg.actions_len.value))
    if msg.actions_len is not 0:
        print_actions(msg.actions) #TODO: print_actions in part of "Multipurpose port functions" in 1.0. Can I use those functions here?
        print_data(msg.data)
    return 0


# ################## OFPT_FLOW_MOD ############################


def print_ofpt_flow_mod(msg):
    # Print main flow_mod options
    string = ('FlowMod - Cookie/Mask: %s/%s Table_id: %s Command: %s '
              'Idle/Hard Timeouts: %s/%s\nFlowMod - Priority: %s '
              'Buffer ID: %s Out Port: %s Out Group: %s Flags: %s Pad: %s')

    flags = green(dissector.get_flow_mod_flags(msg.flags.value))
    port = green(dissector.get_phy_port_no(msg.out_port.value))
    command = green(dissector.get_flow_mod_command(msg.command.value))
    print(string % (msg.cookie, msg.cookie_mask,
                    msg.table_id, command, msg.idle_timeout,
                    msg.hard_timeout, green(msg.priority),
                    msg.buffer_id, port, msg.out_group,
                    flags, print_pad(msg.pad)))

    print_match_type(msg.match)
    print_instruction(msg.instructions)


def print_match_type(match):
    print('Matches - Type: %s Length: %s' %
          (dissector.get_match_type(match.match_type.value),
           match.length))
    # print oxm_fields
    print_match_oxm_fields(match.oxm_match_fields)


def print_match_oxm_fields(oxm_fields):
    for oxm in oxm_fields:
        print_match_generic(oxm)
        print_match_oxm(oxm)


def print_match_generic(oxm):
    print(' OXM Match: Class: %s Length: %s HasMask: %s Field: %s: Value: ' %
          (dissector.get_ofp_oxm_class(oxm.oxm_class.value),
           oxm.oxm_length.value,
           oxm.oxm_hasmask,
           green(dissector.get_flow_match_fields(oxm.oxm_field))), end='')


def print_match_oxm(oxm):
    if oxm.oxm_hasmask == 0:
        if oxm.oxm_field in [0]:
            oxm.oxm_value = int.from_bytes(oxm.oxm_value, byteorder='big')
            oxm.oxm_value = dissector.get_phy_port_no(oxm.oxm_value)
        # DL_DST or DL_SRC
        elif oxm.oxm_field in [3, 4, 24, 25, 32, 33]:
            print(green(libs.tcpiplib.prints.eth_addr(oxm.oxm_value)))
            return
        # DL_TYPE
        elif oxm.oxm_field in [5]:
            oxm.oxm_value = int.from_bytes(oxm.oxm_value, byteorder='big')
            oxm.oxm_value = hex(oxm.oxm_value)
        # DL_VLAN
        elif oxm.oxm_field == 6:
            if oxm.oxm_value == 0:
                oxm.oxm_value = 'OFPVID_NONE (UNTAGGED)'
            else:
                # 0x1xxx Bit 1 indicates VLAN. Removing this bit to
                # get the VID
                oxm.oxm_value = int.from_bytes(oxm.oxm_value, byteorder='big')
                oxm.oxm_value -= 4096

        # NW_SRC or NW_DST
        elif oxm.oxm_field in [11, 12, 22, 23]:
            oxm.oxm_value = libs.tcpiplib.prints.get_ip_from_long(oxm.oxm_value)
        # IPv6 Extensions
        elif oxm.oxm_field in [39]:
            extensions = of13.parser.parse_ipv6_extension_header(oxm.oxm_value)
            for i in extensions:
                print(green(libs.openflow.of13.dissector.get_ipv6_extension(i))),

        print('%s' % green(oxm.oxm_value))

    elif oxm.oxm_hasmask == 1:
        if oxm.oxm_field in [3, 4, 24, 25]:
            oxm.oxm_value = libs.tcpiplib.prints.eth_addr(oxm.oxm_value)
            oxm.payload.mask = libs.tcpiplib.prints.eth_addr(oxm.payload.mask)
        if oxm.oxm_field in [11, 12, 22, 23]:
            oxm.oxm_value = libs.tcpiplib.prints.get_ip_from_long(oxm.oxm_value)
            oxm.payload.mask = libs.tcpiplib.prints.get_ip_from_long(oxm.payload.mask)

        print('%s/%s' % (green(oxm.payload.value), green(oxm.payload.mask)))


def print_instruction(instructions):
    print('Flow Instructions:')
    for instruction in instructions:
        print(' Instruction: Type %s Length: %s' %
              (instruction.instruction_type.value, instruction.length))
        for action in instruction.actions:
            print('  Action - Type %s Length %s' % (green(action.action_type), action.length), end='')
            if action.action_type == 0:
                port_name = "Controller(4294967293)" if action.port == 4294967293 else action.port
                print(" Port %s Max_Len %s Pad %s" %
                      (green(port_name), action.max_length, print_pad(action.pad)))
            # PUSH_VLAN
            elif action.action_type == 17:
                print(" Ethertype: %s" % green(hex(action.ethertype.value)))
            # POP_VLAN
            elif action.action_type == 18:
                pass
            # SET_FIELD
            elif action.action_type == 25:
                if action.field.oxm_field == 6:  # VLAN
                    vlan = unpack('!H', action.field.oxm_value)[0] & 4095
                    print(" VLAN_VID: %s" % green(vlan))
                else:
                    print("ATTENTION!!!!!")
                    print(action.field.oxm_field)
            # SET_QUEUE
            elif action.action_type == 21:
                print(('Action - Type: %s Length: %s Queue ID: %s'
                       ) %
                      (action.length, green(action.queue_id.value)))
            # TODO: do I continue creating print msgs for all the actions in the instructions or just the ones we use?
            else:
                print("ATTENTION!!!!!")
                print()

# ################## OFPT_GROUP_MOD ############################


def print_ofpt_group_mod(msg):
    """Page 82"""
    return 0


# ################## OFPT_PORT_MOD ############################


def print_ofpt_port_mod(msg):
    """
        Args:
            msg: OpenFlow message unpacked by python-openflow | PAGE 84
    """
    print('PortMod Port_no: %s HW_Addr: %s Pad: %s' %
          (yellow(msg.port_no.value), yellow(msg.hw_addr.value), msg.pad))
    return 0


# ################## OFPT_TABLE_MOD ############################


def print_ofpt_table_mod(msg):
    return 0


# ################## OFPT_MULTIPART_REQUEST ############################


def print_ofpt_multipart_request(msg):
    return 0


# ################## OFPT_MULTIPART_REPLY ############################


def print_ofpt_multipart_reply(msg):
    return 0


# ############ OFPT_BARRIER_REQUEST ####################


def print_ofpt_barrier_request(msg):
    return 0


# ############ OFPT_BARRIER_REPLY ####################


def print_ofpt_barrier_reply(msg):
    return 0


# ############ OFPT_QUEUE_GET_CONFIG_REQUEST ####################


def print_ofpt_queue_get_config_request(msg):
    return 0


# ############## OFPT_QUEUE_GET_CONFIG_REPLY ####################


def print_ofpt_queue_get_config_reply(msg):
    return 0


# ##################### OFPT_ROLE_REQUEST #####################


def print_ofpt_role_request(msg):
    return 0


# ################### OFPT_ROLE_REPLY ########################


def print_ofpt_role_reply(msg):
    return 0


# ############### OFPT_GET_ASYNC_REQUEST #####################


def print_ofpt_get_async_request(msg):
    return 0


# ################## OFPT_GET_ASYNC_REPLY #####################


def print_ofpt_get_async_reply(msg):
    return 0


# ################## OFPT_GET_ASYNC ###########################


def print_ofpt_set_async(msg):
    return 0


# ################## OFPT_METER_MOD ############################


def print_ofpt_meter_mod(msg):
    return 0
