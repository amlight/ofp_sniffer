"""
    OpenFlow 1.3 prints
"""
from struct import unpack
from hexdump import hexdump
from pyof.foundation.basic_types import BinaryData
from pyof.foundation.basic_types import FixedTypeList
import libs.tcpiplib.prints
from libs.gen.prints import red, green, yellow
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
                     13: print_ofpt_packet_out,  # ok
                     14: print_ofpt_flow_mod,  # ok
                     15: print_ofpt_group_mod,  # pending
                     16: print_ofpt_port_mod,  # pending
                     17: print_ofpt_table_mod,  # ok
                     18: print_ofpt_multipart_request,  # ok, but missing payload
                     19: print_ofpt_multipart_reply,  # ok, but missing payload
                     20: print_ofpt_barrier_request,  # ok
                     21: print_ofpt_barrier_reply,  # ok
                     22: print_ofpt_queue_get_config_request,  # ok
                     23: print_ofpt_queue_get_config_reply,  # pending
                     24: print_ofpt_role_request,  # ON HOLD
                     25: print_ofpt_role_reply,  # ON HOLD
                     26: print_ofpt_get_async_request,  # ON HOLD
                     27: print_ofpt_get_async_reply,  # ON HOLD
                     28: print_ofpt_set_async,  # ON HOLD
                     29: print_ofpt_meter_mod  # ON HOLD
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
    if isinstance(msg.data, BinaryData) and len(msg.data) > 0:
        print("Echo Request - Data: \"%s\"" % msg.data.value.decode("utf-8"))
    return 0


# ################## OFPT_ECHO_REPLY ############################


def print_ofpt_echo_reply(msg):
    if isinstance(msg.data, BinaryData) and len(msg.data) > 0:
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

        if next_protocol in [34984]:  # has QinQ
            qinq = data.pop(0)
            libs.tcpiplib.prints.print_qinq(qinq)
            next_protocol = qinq.protocol

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
    print_of_ports(msg.desc)

    return 0


# ################## OFPT_PACKET_OUT ############################


def print_ofpt_packet_out(msg):
    """
        Args:
            msg: OpenFlow message unpacked by python-openflow  ; PAGE 107 MANUAL
    """
    print('PacketOut: buffer_id: %s in_port: %s actions_len: %s' %
          (hex(msg.buffer_id.value),
           green(dissector.get_phy_port_no(msg.in_port.value)),
           msg.actions_len.value))
    if msg.actions_len is not 0:
        print(" Actions:")
        for action in msg.actions:
            print("  ", end="")
            print_action(action)
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


def print_action(action):
    """Function to print the content of openflow actions"""
    if action.action_type == 0:
        port_name = dissector.get_phy_port_no(action.port.value)
        print(" Output Port %s Max_Len %s Pad %s" %
              (green(port_name), action.max_length, print_pad(action.pad)))
    # SetMPLSTTL
    elif action.action_type == 15:
        print("ATTENTION!!!!!")
    # PUSH_VLAN
    elif action.action_type == 17:
        print(" Ethertype: %s" % green(hex(action.ethertype.value)))
    # CopyTTLOut, CopyTTLIn, DecMPLSTTL, POP_VLAN, PopMPLS, DecNWTTL, PopPBB
    elif action.action_type in [11, 12, 16, 18, 20, 24, 27]:
        print()
    # PushMPLS
    elif action.action_type == 19:
        print("ATTENTION!!!!!")
    # SET_QUEUE
    elif action.action_type == 21:
        print(' Queue ID: %s' % green(action.queue_id.value))
    # Group
    elif action.action_type == 22:
        print("ATTENTION!!!!!")
    # SetNWTTL
    elif action.action_type == 23:
        print("ATTENTION!!!!!")
    # SET_FIELD
    elif action.action_type == 25:
        # TODO: LEVERAGE FUNCTION BELOW IN THE FUTURE FOR ALL THE OXM_MATCH
        # print_match_oxm(action.field)
        if action.field.oxm_field == 6:  # VLAN
            vlan = unpack('!H', action.field.oxm_value)[0] & 4095
            print(" Set VLAN_VID: %s" % green(vlan))
        elif action.field.oxm_field == 3:  # ETH_DST
            print(" Set ETH_DST: %s" % green(libs.tcpiplib.prints.eth_addr(action.field.oxm_value)))
        elif action.field.oxm_field == 4:  # ETH_SRC
            print(" Set ETH_SRC: %s" % green(libs.tcpiplib.prints.eth_addr(action.field.oxm_value)))
        else:
            print("  ATTENTION!!!!!")
            print(action.field.oxm_field)
    # PushPBB
    elif action.action_type == 26:
        print("ATTENTION!!!!!")
    # Experimenter
    elif action.action_type == 65535:
        print("ATTENTION!!!!!")


def print_instruction(instructions):
    print('Flow Instructions:')
    for instruction in instructions:
        print(' Instruction: Type %s Length: %s' %
              (dissector.get_instructions(instruction.instruction_type.value), instruction.length))
        # GotoTable
        if instruction.instruction_type.value == 1:
            print(" Goto Table_ID: %s" % green(instruction.table_id.value))
        # WriteMetadata
        if instruction.instruction_type.value == 2:
            print(" MetaData: %s MetaData_Mask: %s" %
                  (green(hex(instruction.metadata.value)), green(hex(instruction.metadata_mask.value))))
        # WriteActions, ApplyActions, ClearActions
        if instruction.instruction_type.value in [3,4,5]:
            for action in instruction.actions:
                print('  Action - Type %s Length %s' % (green(action.action_type), action.length), end='')
                print_action(action)
        # Meter
        if instruction.instruction_type.value == 6:
            print("Meter_ID: %s" % green(hex(instruction.meter_id.value)))
        # Experimenter
        if instruction.instruction_type.value == 65535:
            print("Experimenter")


# ################## OFPT_GROUP_MOD ############################


def print_ofpt_group_mod(msg):
    """
        Args:
            msg: OpenFlow message unpacked by python-openflow | PAGE 82
    """
    command = green(dissector.get_group_mod_command(msg.command.value))
    type = green(dissector.get_group_mod_type(msg.command.value))

    print('GroupMod Command: %s Type: %s Pad: %s Group_id: %s\n'
          'Bucket[lenght]: %s Bucket[weight]: %s Bucket[watch_port]: %s Bucket[watch_group]: %s' %
          (command, type, msg.pad, green(msg.group_id.value), msg.buckets[0].length.value,
           msg.buckets[0].weight.value, hex(msg.buckets[0].watch_port.value),
           hex(msg.buckets[0].watch_group.value)))
    print("Bucket[actions]:")
    for action in msg.buckets[0].actions:
        print_action(action)

    return 0


# ################## OFPT_PORT_MOD ############################


def print_ofpt_port_mod(msg):
    """
        Args:
            msg: OpenFlow message unpacked by python-openflow | PAGE 84
    """

    def _print_port_mod_config_mask(variable, name):
        """The mask field is used to select bits in the config field to change.
        The advertise field has no mask; all port features change together."""

        print('PortMod %s: ' % name, end='')
        printed = False
        variable = _parse_phy_curr(variable)
        for i in variable:
            print(red(dissector.get_phy_config(i)), end='')
            printed = True
        else:
            _dont_print_0(printed)
        print()

    print('PortMod Port: %s HW_Addr: %s Config: %s Mask: %s Advertise: %s' %
          (yellow(msg.port_no.value), yellow(msg.hw_addr.value),
           msg.config.value, msg.mask, msg.advertise))
    _print_port_mod_config_mask(msg.config.value, 'config')
    _print_port_mod_config_mask(msg.mask.value, 'mask')
    _print_port_mod_config_mask(msg.advertise.value, 'advertise')

    return 0


# ################## OFPT_TABLE_MOD ############################


def print_ofpt_table_mod(msg):
    """
            Args:
                msg: OpenFlow message unpacked by python-openflow
        """

    config = dissector.get_table_mod_confi(msg.config.value)
    for i in config:
        print(dissector.get_table_mod_config(i), end='')
        printed = True
    else:
        printed = _dont_print_0(printed)
    print()

    print('TableMod Table_ID: %s Pad: %s Config: %s' %
          (green(msg.table_id.value), msg.pad, msg.config.value))

    return 0


# ################## OFPT_MULTIPART_REQUEST ############################


def print_ofpt_multipart_request(msg):
    # Print main multipart_request options
    string = 'Body - Type: %s Flags: %s Pad: %s'

    flags = green(dissector.get_multipart_request_flags(msg.flags.value))

    print(string % (msg.multipart_type, flags, msg.pad))

    return 0


# ################## OFPT_MULTIPART_REPLY ############################


def print_ofpt_multipart_reply(msg):
    # Print main multipart_reply options
    string = 'Body - Type: %s Flags: %s Pad: %s'

    flags = green(dissector.get_multipart_reply_flags(msg.flags.value))

    print(string % (msg.multipart_type, flags, msg.pad))

    return 0


# ############ OFPT_BARRIER_REQUEST ####################


def print_ofpt_barrier_request(msg):
    """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
    pass


# ############ OFPT_BARRIER_REPLY ####################


def print_ofpt_barrier_reply(msg):
    """

            Args:
                msg: OpenFlow message unpacked by python-openflow
            """
    pass


# ############ OFPT_QUEUE_GET_CONFIG_REQUEST ####################


def print_ofpt_queue_get_config_request(msg):
    # Print main flow_removed options
    string = 'Body - Port: %s Pad: %s'

    print(string % (msg.port, msg.pad))

    return 0


# ############## OFPT_QUEUE_GET_CONFIG_REPLY ####################


def print_ofpt_queue_get_config_reply(msg):
    # Print main flow_removed options
    string = 'Body - Port: %s Pad: %s'

    print(string % (msg.port, msg.queue))

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
    """
           These  commands  manage  the  meter  table  in  an  OpenFlow  switch.  In each case, meter
       specifies a meter entry in the format described in Meter Syntax.
    """
    # Print main meter_mod options
    string = 'Body - Command: %s Flags: %s Meter_OD: %s'

    flags = green(dissector.get_meter_mod_flags(msg.flags.value))
    command = green(dissector.get_meter_mod_command(msg.command.value))

    print(string % (command, flags, msg.meter_id,))



# ******************** Multipurpose port functions *******************************


def _dont_print_0(printed):
    if printed is False:
        print('0', end='')
    return False


def print_port_field(port_id, variable, name):
    port_id = '%s' % green(port_id)
    printed = False

    print('Port_id: %s - %s: ' % (port_id, name), end='')
    variable = _parse_phy_curr(variable)
    for i in variable:
        print(dissector.get_phy_feature(i) + ' ', end='')
        printed = True
    else:
        _dont_print_0(printed)
    print()


def print_ofp_phy_port(port):
    port_id = '%s' % green(port.port_no)

    print('Port_id: %s - hw_addr: %s name: %s' % (
          port_id, green(port.hw_addr), green(port.name)))

    print('Port_id: %s - config: ' % port_id, end='')
    printed = False
    config = _parse_phy_config(port.config.value)
    for i in config:
        print(dissector.get_phy_config(i), end='')
        printed = True
    else:
        printed = _dont_print_0(printed)
    print()

    print('Port_id: %s - state: ' % port_id, end='')
    state = _parse_phy_state(port.state.value)
    for i in state:
        print(dissector.get_phy_state(i), end='')
        printed = True
    else:
        _dont_print_0(printed)
    print()

    print_port_field(port_id, port.curr, 'curr')
    print_port_field(port_id, port.advertised, 'advertised')
    print_port_field(port_id, port.supported, 'supported')
    print_port_field(port_id, port.peer, 'peer')


def print_of_ports(ports):
    if not isinstance(ports, FixedTypeList):
        print_ofp_phy_port(ports)
    else:
        for port in ports:
            print_ofp_phy_port(port)


def _parse_bitmask(bitmask, array):
    size = len(array)
    for i in range(0, size):
        mask = 2**i
        aux = bitmask & mask
        if aux == 0:
            array.remove(mask)
    return array


def _parse_capabilities(capabilities):
    caps = [1, 2, 4, 8, 16, 32, 64, 128]
    return _parse_bitmask(capabilities, caps)


def _parse_actions(actions):
    acts = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]
    return _parse_bitmask(actions, acts)


def _parse_phy_config(config):
    confs = [1, 2, 4, 8]
    return _parse_bitmask(config, confs)


def _parse_phy_state(state):
    states = [1, 2, 4, 8, 16]
    return _parse_bitmask(state, states)


def _parse_phy_curr(values):
    confs = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
             4096, 8192, 16384, 32768]
    return _parse_bitmask(values, confs)