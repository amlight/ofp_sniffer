"""
    Prints for OpenFlow 1.0 only
"""
from hexdump import hexdump
from pyof.foundation.basic_types import BinaryData
from pyof.foundation.basic_types import FixedTypeList
from libs.gen.prints import red, green, yellow
import libs.tcpiplib.tcpip
import libs.openflow.of10.dissector as dissector
from libs.tcpiplib.prints import print_openflow_header
from libs.tcpiplib.process_data import dissect_data


# ******************** Points to the right printing function ****************


def prints_ofp(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    Returns:

    """

    try:
        of_types = {0: print_ofpt_hello,
                    1: print_ofpt_error,
                    2: print_ofpt_echo_request,
                    3: print_ofpt_echo_reply,
                    4: print_ofpt_vendor,
                    5: print_ofpt_features_request,
                    6: print_ofpt_features_reply,
                    7: print_ofpt_get_config_request,
                    8: print_ofpt_get_config_reply,
                    9: print_ofpt_set_config,
                    10: print_ofpt_packet_in,
                    11: print_ofpt_flow_removed,
                    12: print_ofpt_port_status,
                    13: print_ofpt_packet_out,
                    14: print_ofpt_flow_mod,
                    15: print_ofpt_port_mod,
                    16: print_ofpt_stats_request,
                    17: print_ofpt_stats_reply,
                    18: print_ofpt_barrier_request,
                    19: print_ofpt_barrier_reply,
                    20: print_ofpt_queue_get_config_request,
                    21: print_ofpt_queue_get_config_reply}

        return of_types[msg.header.message_type.value](msg)
    except Exception as err:
        print("Error: %s" % err)


# *************************** OFPT_HELLO *************************************


def print_ofpt_hello(msg):
    """ OFPT_HELLO has no payload, so it does not print anything.
    It is here just for educational purposes.
    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    pass


# *************************** OFPT_ERROR **************************************


def print_ofpt_error(msg):
    """ Prints OFPT_ERROR messages. msg.data is the error payload, which is
    the OpenFlow message that triggered the error.

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    etype, ecode = dissector.get_ofp_error(msg.error_type.value, msg.code.value)
    print('OpenFlow Error - Type: %s Code: %s' % (red(etype), red(ecode)))

    if not isinstance(msg.data, BinaryData):
        print('OpenFlow Error Message:\n------ BEGIN ------')
        print_openflow_header(msg.data)
        prints_ofp(msg.data)
        print('OpenFlow Error Message:\n------- END -------')
    else:
        print(red('OpenFlow Error Data could not be processed!!'))


# *************************** OFPT_ECHO_REQUEST ******************************


def print_ofpt_echo_request(msg):
    """ Prints OFPT_ECHO_REQUEST messages. msg.data can be any content. The
    controller that sent the ECHO knows what it means. As a sniffer, we do
    not know what it means so we print in hex.

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    if len(msg.data.value) > 0:
        hexdump(msg.data.value)


# *************************** OFPT_ECHO_REPLY ********************************


def print_ofpt_echo_reply(msg):
    """ Prints OFPT_ECHO_REPLY messages. msg.data can be any content. The
    controller that sent the ECHO knows what it means. As a sniffer, we do
    not know what it means so we print in hex.

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    if len(msg.data.value) > 0:
        hexdump(msg.data.value)


# ****************************** OFPT_VENDOR *********************************


def print_ofpt_vendor(msg):
    """ Prints OFPT_VENDOR messages. Any vendor can extend the OpenFlow
    specification with new messages. OVS/NICIRA uses this message a lot.
    We do not dissect vendor-specific messages but it would be great to have
    such support (which means we are looking for volunteers!).

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    vendor = dissector.get_ofp_vendor(msg.vendor.value)
    print('OpenFlow Vendor: %s' % vendor)


# ************************ OFPT_FEATURES_REQUEST *****************************


def print_ofpt_features_request(msg):
    """ OFPT_FEATURES_REQUEST has no payload, so this function does not print
    anything. It is here just for educational purposes.

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    pass


# ************************* OFPT_FEATURES_REPLY *****************************


def print_ofpt_features_reply(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    dpid = msg.datapath_id
    print('FeatureRes - datapath_id: %s n_buffers: %s n_tables: %s, pad: %s'
          % (green(dpid), msg.n_buffers, msg.n_tables, msg.pad))

    print('FeatureRes - Capabilities: ', end='')
    capabilities = _parse_capabilities(msg.capabilities)
    for i in capabilities:
        print(dissector.get_feature_res_capabilities(i) + ' ', end='')
    print()

    print('FeatureRes - Actions: ', end='')
    actions = _parse_actions(msg.actions)
    for i in actions:
        print(dissector.get_feature_res_actions(i) + ' ', end='')
    print()

    print_of_ports(msg.ports)


# ************************* OFPT_GET_CONFIG_REQUEST *****************************


def print_ofpt_get_config_request(msg):
    """ OFPT_GET_CONFIG_REQUEST has no payload, so this function does not print
    anything. It is here just for educational purposes.
    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    pass


# ************************* OFPT_GET_CONFIG_REPLY *******************************


def print_ofpt_get_config_reply(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    print('OpenFlow GetConfigRes - Flag: %s Miss_send_len: %s' %
          (msg.flags, msg.miss_send_len))


# ************************* OFPT_SET_CONFIG **********************************


def print_ofpt_set_config(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    flags = str(msg.flags)
    print('OpenFlow SetConfig - Flag: %s Miss_send_len: %s' %
          (yellow(flags.split('.')[1]), msg.miss_send_len))


# ************************* OFPT_PACKET_IN ***********************************


def print_ofpt_packet_in(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    print('PacketIn: buffer_id: %s total_len: %s in_port: %s reason: %s '
          'pad: %s' %
          (hex(msg.buffer_id.value), msg.total_len.value,
           green(msg.in_port.value), green(msg.reason.value), msg.pad))
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


# ************************* OFPT_FLOW_REMOVED ********************************


def print_ofpt_flow_removed(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    print_ofp_match(msg.match)

    string = ('Body - Cookie: %s Priority: %s Reason: %s Pad: %s\nBody - '
              'Duration Secs/NSecs: %s/%s Idle Timeout: %s Pad2: %s'
              ' Packet Count: %s Byte Count: %s')

    print(string % (msg.cookie, msg.priority, red(msg.reason),
                    msg.pad, msg.duration_sec, msg.duration_nsec,
                    msg.idle_timeout, msg.pad2,
                    msg.packet_count, msg.byte_count))


# ************************* OFPT_PORT_STATUS ********************************


def print_ofpt_port_status(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    print('OpenFlow PortStatus - Reason: %s Pad: %s' %
          (msg.reason, msg.pad))
    print_of_ports(msg.desc)


# ************************* OFPT_PACKET_OUT ********************************


def print_ofpt_packet_out(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    print('PacketOut: buffer_id: %s in_port: %s actions_len: %s' %
          (hex(msg.buffer_id.value),
           green(dissector.get_phy_port_id(msg.in_port.value)),
           msg.actions_len.value))
    if msg.actions_len is not 0:
        print_actions(msg.actions)
        print_data(msg.data)


# ************************* OFPT_FLOW_MOD *********************************


def print_ofpt_flow_mod(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    print_ofp_match(msg.match)
    print_ofp_body(msg)
    print_actions(msg.actions)
    # Print OVS is deactivated for now
    # print_ofp_ovs(msg)


def print_ofp_match(match):
    """

    Args:
        match:
    """
    print('Match - ', end='')
    for match_item in match.__dict__:
        match_item_value = match.__dict__[match_item]
        if match_item_value.value not in [0, "00:00:00:00:00:00", "0.0.0.0", 65535]:
            if match_item is 'dl_vlan' and match_item_value.value not in [65535]:
                match_item_value = dissector.get_vlan(match_item_value.value)
            elif match_item is 'wildcards':
                match_item_value = hex(match_item_value.value)
            elif match_item is 'dl_type' and match_item_value.value not in [65535]:
                match_item_value = libs.tcpiplib.tcpip.get_ethertype(match_item_value.value)
            elif match_item in ['pad1', 'pad2']:
                continue

            print("%s: %s " % (match_item, green(match_item_value)), end='')
    print()


def print_ofp_body(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    string = ('Body - Cookie: %s Command: %s Idle/Hard Timeouts: '
              '%s/%s\nBody - Priority: %s Buffer ID: %s Out Port: %s Flags: %s')
    command = green(dissector.get_ofp_command(msg.command.value))
    flags = green(dissector.get_ofp_flags(msg.flags.value))
    out_port = green(dissector.get_phy_port_id(msg.out_port.value))

    print(string % (msg.cookie.value, command, msg.idle_timeout, msg.hard_timeout,
                    green(msg.priority), msg.buffer_id.value, out_port, flags))


def print_actions(actions):
    """

    Args:
        actions:
    """
    for action in actions:
        print_ofp_action(action)


def print_ofp_action(action):
    """

    Args:
        action:
    """
    if action.action_type == 0:
        port = dissector.get_phy_port_id(action.port.value)
        print('Action - Type: %s Length: %s Port: %s '
              'Max Length: %s' %
              (green('OUTPUT'), action.length, green(port), action.max_length))

    elif action.action_type == 1:
        print('Action - Type: %s Length: %s VLAN ID: %s Pad: %s' %
              (green('SetVLANID'), action.length, green(str(action.vlan_id.value)), action.pad2))

    elif action.action_type == 2:
        print('Action - Type: %s Length: %s VLAN PCP: %s Pad: %s' %
              (green('SetVLANPCP'), action.length, green(str(action.vlan_pcp.value)), action.pad))

    elif action.action_type == 3:
        print('Action - Type: %s Length: %s' %
              (green('StripVLAN'), action.length))

    elif action.action_type == 4:
        print('Action - Type: %s Length: %s SetDLSrc: %s Pad: %s' %
              (green('SetDLSrc'), action.length, green(action.dl_src),
               action.pad))

    elif action.action_type == 5:
        print('Action - Type: %s Length: %s SetDLDst: %s Pad: %s' %
              (green('SetDLDst'), action.length, green(action.dl_dst),
               action.pad))

    elif action.action_type == 6:
        print('Action - Type: %s Length: %s SetNWSrc: %s' %
              (green('SetNWSrc'), action.length, green(action.nw_addr)))

    elif action.action_type == 7:
        print('Action - Type: %s Length: %s SetNWDst: %s' %
              (green('SetNWDst'), action.length, green(action.nw_addr)))

    elif action.action_type == 8:
        print('Action - Type: %s Length: %s SetNWTos: %s Pad: %s' %
              (green('SetNWTos'), action.length, green(action.nw_tos.value),
               action.pad))

    elif action.action_type == 9:
        print('Action - Type: %s Length: %s SetTPSrc: %s Pad: %s' %
              (green('SetTPSrc'), action.length, green(action.port_no.value),
               action.pad))

    elif action.action_type == int('a', 16):
        print('Action - Type: %s Length: %s SetTPDst: %s Pad: %s' %
              (green('SetTPDst'), action.length, green(action.port_no.value),
               action.pad))

    elif action.action_type == int('b', 16):
        print(('Action - Type: %s Length: %s Enqueue: %s Pad: %s'
               ' Queue: %s') %
              (green('Enqueue'), action.length, green(action.port_no.value),
               action.pad, green(action.queue_id.value)))

    elif action.action_type == int('ffff', 16):
        print('Action - Type:  %s Length: %s Vendor: %s' %
              (green('VENDOR'), action.length, green(action.vendor)))

    else:
        print('Unknown Action Type')


# ************************* OFPT_PORT_MOD *********************************


def print_ofpt_port_mod(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
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

    print('PortMod Port_no: %s HW_Addr: %s Pad: %s' %
          (yellow(msg.port_no.value), yellow(msg.hw_addr.value), msg.pad))
    _print_port_mod_config_mask(msg.config.value, 'config')
    _print_port_mod_config_mask(msg.mask.value, 'mask')
    _print_port_mod_config_mask(msg.advertise.value, 'advertise')


# ************************* OFPT_STATS_REQUEST **********************************


def print_ofpt_stats_request(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    def print_ofpt_stats_request_description(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
        body = str(msg.body_type)
        print('StatReq Type: %s' % body.split('.')[1])

    def print_ofpt_stats_request_flow_aggregate(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
        if msg.body_type == 1:
            type_name = 'Flow'
        else:
            type_name = 'Aggregate'
        body_type = "%s" % msg.body_type
        print('StatReq Type: %s(%s)' % (type_name, body_type.split('.')[1]))
        print_ofp_match(msg.body[0].match)
        out_port = dissector.get_phy_port_id(msg.body[0].out_port.value)
        print('StatReq Table_id: %s Pad: %s Out_Port: %s' % (msg.body[0].table_id.value,
              msg.body[0].pad, out_port))

    def print_ofpt_stats_request_table(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
        body = "%s" % msg.body_type
        print('StatReq Type: %s' % body.split('.')[1])

    def print_ofpt_stats_request_port(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
        port_number = dissector.get_phy_port_id(msg.body[0].port_no.value)
        print('StatReq Type: Port(4) Port_Number: %s Pad: %s' %
              (green(port_number), msg.body[0].pad))

    def print_ofpt_stats_request_queue(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
        port_number = dissector.get_phy_port_id(msg.body[0].port_no.value)
        print('StatReq Type: OFPST_QUEUE: Port_Number: %s Pad: %s Queue_id: %s' %
              (green(port_number), msg.body[0].pad, msg.body[0].queue_id))

    def print_ofps_stats_request_vendor(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
        vendor_id = dissector.get_ofp_vendor(msg.body[0].vendor.value)
        print('StatReq Type: Vendor(%s): Vendor_ID: %s' %
              (hex(msg.body_type.value), vendor_id))
        print("StatReq Vendor Data:")
        hexdump(msg.body[0].body.value)

    if msg.body_type == 0:
        print_ofpt_stats_request_description(msg)
    elif msg.body_type == 1 or msg.body_type == 2:
        print_ofpt_stats_request_flow_aggregate(msg)
    elif msg.body_type == 3:
        print_ofpt_stats_request_table(msg)
    elif msg.body_type == 4:
        print_ofpt_stats_request_port(msg)
    elif msg.body_type == 5:
        print_ofpt_stats_request_queue(msg)
    elif msg.body_type == 65535:
        print_ofps_stats_request_vendor(msg)


# ************************* OFPT_STATS_REPLY **********************************


def print_ofpt_stats_reply(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """

    def print_ofpt_stats_reply_description(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
        print('StatRes Type: OFPST_DESC')
        print('StatRes mfr_desc: %s' % msg.body.mfr_desc)
        print('StatRes hw_desc: %s' % msg.body.hw_desc)
        print('StatRes sw_desc: %s' % msg.body.sw_desc)
        print('StatRes serial_num: %s' % msg.body.serial_num)
        print('StatRes dp_desc: %s' % msg.body.dp_desc)

    def print_ofpt_stats_reply_flow_array(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """

        def print_ofpt_stats_reply_flow(flow):
            """

            Args:
                msg: OpenFlow message unpacked by python-openflow
            """
            print('StatRes Type: Flow(1)')
            print('StatRes Length: %s Table_id: %s Pad: %s ' %
                  (flow.length, flow.table_id, flow.pad))
            print('StatRes ', end='')
            print_ofp_match(flow.match)
            print('StatRes duration_sec: %s, duration_nsec: %s, priority: %s,'
                  ' idle_timeout: %s, hard_timeout: %s, pad: %s, cookie: %s,'
                  ' packet_count: %s, byte_count: %s' %
                  (flow.duration_sec, flow.duration_nsec,
                   flow.priority, flow.idle_timeout,
                   flow.hard_timeout, flow.pad,
                   flow.cookie,
                   flow.packet_count, flow.byte_count))
            print('StatRes ', end='')
            print_actions(flow.actions)

        if len(msg.body) == 0:
            print('StatRes Type: Flow(1)\nNo Flows')
            return

        for flow in msg.body:
            print_ofpt_stats_reply_flow(flow)

    def print_ofpt_stats_reply_aggregate(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """
        print('StatRes Type: Aggregate(2)')
        print('StatRes packet_count: %s, byte_count: %s flow_count: %s '
              'pad: %s' %
              (msg.stats.packet_count, msg.stats.byte_count,
               msg.stats.flow_count, msg.stats.pad))

    def print_ofpt_stats_reply_table_array(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """

        def print_ofpt_stats_reply_table(table):
            """

            Args:
                msg: OpenFlow message unpacked by python-openflow
            """
            print('StatRes table_id: %s, pad: %s, name: "%s", wildcards: %s, '
                  'max_entries: %s, active_count: %s, lookup_count: %s, '
                  'matched_count: %s' %
                  (table.table_id.value, table.pad, table.name.value, hex(table.wildcards.value),
                   table.max_entries.value, table.active_count.value,
                   table.count_lookup.value, table.count_matched.value))

        if len(msg.body) == 0:
            print('StatRes Type: Table(3)\nNo Tables')
            return

        print('StatRes Type: Table(3)')
        for table in msg.body:
            print_ofpt_stats_reply_table(table)

    def print_ofp_stats_reply_port_array(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """

        def print_ofpt_stats_reply_port(port):
            """

            Args:
                msg: OpenFlow message unpacked by python-openflow
            """
            print('StatRes Type: Port(4)')
            print('StatRes port_number: %s rx_packets: %s rx_bytes: %s rx_errors: %s'
                  ' rx_crc_err: %s rx_dropped: %s rx_over_err: %s rx_frame_err: %s\n'
                  'StatRes port_number: %s tx_packets: %s tx_bytes: %s tx_errors: %s'
                  ' tx_dropped: %s collisions: %s pad: %s' %
                  (red(port.port_no), port.rx_packets,
                   port.rx_bytes, port.rx_errors, port.rx_crc_err,
                   port.rx_dropped, port.rx_over_err,
                   port.rx_frame_err, red(port.port_no),
                   port.tx_packets, port.tx_bytes, port.tx_errors,
                   port.tx_dropped, port.collisions, port.pad))

        if len(msg.body) == 0:
            print('StatRes Type: Port(4)\nNo Ports')
            return
        for port in msg.body:
            print_ofpt_stats_reply_port(port)

    def print_ofpt_stats_reply_queue_array(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """

        def print_ofpt_stats_reply_queue(queue):
            """

            Args:
                msg: OpenFlow message unpacked by python-openflow
            """
            print('StatRes Type: Queue(5)')
            print('StatRes queue_id: %s length: %s pad: %s'
                  ' tx_bytes: %s tx_packets: %s tx_errors: %s' %
                  (queue.queue_id, queue.length, queue.pad,
                   queue.tx_bytes, queue.tx_packets, queue.tx_errors))

        if len(msg.body) == 0:
            print('StatRes Type: Queue(5)\nNo Queues')
            return

        for queue in msg.body:
            print_ofpt_stats_reply_queue(queue)

    def print_ofpt_stats_reply_vendor(msg):
        """

        Args:
            msg: OpenFlow message unpacked by python-openflow
        """

        def print_ofpt_stats_reply_vendor_data(data):
            """

            Args:
                msg: OpenFlow message unpacked by python-openflow
            """
            print('StatRes Vendor Data: ')
            hexdump(data)


        print('StatRes Type: Vendor(%s)' % hex(msg.body_type.value))
        print('StatRes Vendor_Id: %s' % red(hex(msg.body[0].vendor.value)))
        print_ofpt_stats_reply_vendor_data(msg.body[0].body.value)

    if msg.body_type == 0:
        print_ofpt_stats_reply_description(msg)
    elif msg.body_type == 1:
        print_ofpt_stats_reply_flow_array(msg)
    elif msg.body_type == 2:
        print_ofpt_stats_reply_aggregate(msg)
    elif msg.body_type == 3:
        print_ofpt_stats_reply_table_array(msg)
    elif msg.body_type == 4:
        print_ofp_stats_reply_port_array(msg)
    elif msg.body_type == 5:
        print_ofpt_stats_reply_queue_array(msg)
    elif msg.body_type == 65535:
        print_ofpt_stats_reply_vendor(msg)


# ************************* OFPT_BARRIER_REQUEST **********************************


def print_ofpt_barrier_request(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    pass


# ************************* OFPT_BARRIER_REPLY **********************************


def print_ofpt_barrier_reply(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    pass


# ************************* OFPT_QUEUE_GET_CONFIG_REQUEST **********************************


def print_ofpt_queue_get_config_request(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """
    print('QueueGetConfigReq Port: %s Pad: %s' % (msg.port, msg.pad))


# ************************* OFPT_QUEUE_GET_CONFIG_REPLY **********************************


def print_ofpt_queue_get_config_reply(msg):
    """

    Args:
        msg: OpenFlow message unpacked by python-openflow
    """

    def print_ofpt_queue_reply_prop_payload(payload):
        print('Payload: Rate %s Pad: %s' % (payload.rate, payload.pad))

    def print_ofpt_queue_reply_properties(qproperty):
        print('Property: %s Length: %s Pad: %s' %
              (qproperty.property, qproperty.length, qproperty.pad))
        print_ofpt_queue_reply_prop_payload(qproperty.payload)

    def print_ofpt_queue_reply_queue(queue):
        print('Queue_ID: %s Length: %s Pad: %s' %
              (queue.queue_id, queue.length, queue.pad))
        if len(queue.properties) == 0:
            print('QueueGetConfigRes: No Properties')
            return
        for property in queue.properties:
            print_ofpt_queue_reply_properties(property)

    print('QueueGetConfigRes Port: %s Pad: %s' %
          (msg.port, msg.pad))

    if len(msg.queues) == 0:
        print('QueueGetConfigRes: No Queues')
        return

    for queue in msg.queues:
        print_ofpt_queue_reply_queue(queue)


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
    confs = [1, 2, 4, 8, 16, 32, 64]
    return _parse_bitmask(config, confs)


def _parse_phy_state(state):
    states = [1, 2, 4, 8, 16]
    return _parse_bitmask(state, states)


def _parse_phy_curr(values):
    confs = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]
    return _parse_bitmask(values, confs)


# def print_ofp_ovs(msg):
#     """
#         If -o or --print-ovs is provided by user, print a ovs-ofctl add-dump
#     """
#
#     def get_command(command):
#         commands = {0: 'add-flow', 1: 'mod-flows', 3: 'del-flows'}
#         try:
#             return commands[command]
#         except KeyError:
#             return 0
#
#     def get_flag(flag):
#         flags = {0: '', 1: 'send_flow_rem', 2: 'check_overlap', 3: 'Emerg'}
#         try:
#             return flags[flag]
#         except KeyError:
#             return 0
#
#     def get_actions(action_type, action_length, payload):
#         if action_type == 0:
#             port, max_len = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'output:%s' % (port if port != 65533 else 'CONTROLLER')
#         elif action_type == 1:
#             vlan, pad = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_vlan_vid:' + str(vlan)
#         elif action_type == 2:
#             vlan_pc, pad = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_vlan_pcp:' + str(vlan_pc)
#         elif action_type == 3:
#             return 'strip_vlan'
#         elif action_type == 4:
#             setDLSrc, pad = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_dl_src:' + str(eth_addr(setDLSrc))
#         elif action_type == 5:
#             setDLDst, pad = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_dl_dst:' + str(eth_addr(setDLDst))
#         elif action_type == 6:
#             nw_addr = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_nw_src:' + str(nw_addr)
#         elif action_type == 7:
#             nw_addr = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_nw_src:' + str(nw_addr)
#         elif action_type == 8:
#             nw_tos, pad = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_nw_tos:' + str(nw_tos)
#         elif action_type == 9:
#             port, pad = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_tp_src:' + str(port)
#         elif action_type == int('a', 16):
#             port, pad = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'mod_tp_dst:' + str(port)
#         elif action_type == int('b', 16):
#             port, pad, queue_id = libs.openflow.of10.parser.get_action(action_type, payload)
#             return 'set_queue:' + str(queue_id)
#
#     if PrintingOptions().print_ovs is not True:
#         return
#
#     switch_ip = 'SWITCH_IP'
#     switch_port = '6634'
#
#     ofm = []
#     ofactions = []
#
#     ovs_command = get_command(msg.command)
#
#     for K in msg.match.__dict__:
#         if K != 'wildcards':
#             if msg.match.__dict__[K] is not None:
#                 value = "%s=%s," % (K, msg.match.__dict__[K])
#                 ofm.append(value)
#
#     matches = ''.join(ofm)
#
#     if msg.command is not 3:
#         for action in msg.actions:
#                 value = get_actions(action.type, action.length, action.payload)
#                 value = "%s," % value
#                 ofactions.append(value)
#
#         flag = get_flag(msg.flags)
#         print('ovs-ofctl %s tcp:%s:%s \"' % (ovs_command, switch_ip, switch_port), end='')
#         if msg.flags != 0:
#             print('%s,' % flag, end='')
#         if msg.priority != 32678:
#             print('priority=%s,' % msg.priority, end='')
#         if msg.idle_timeout != 0:
#             print('idle_timeout=%s,' % msg.idle_timeout, end='')
#         if msg.hard_timeout != 0:
#             print('hard_timeout=%s,' % msg.hard_timeout, end='')
#         print('%s ' % matches, end='')
#         print('action=%s\"' % ''.join(ofactions))
#     else:
#         ovs_msg_del = 'ovs-ofctl %s tcp:%s:%s %s '
#         print(ovs_msg_del % (ovs_command, switch_ip, switch_port, matches))
