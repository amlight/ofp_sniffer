"""
    Prints for OpenFlow 1.0 only
"""
from hexdump import hexdump

import of10.dissector
import of10.parser
import tcpiplib.prints
import tcpiplib.tcpip
from gen.prints import red, green
from tcpiplib.prints import eth_addr, datapath_id
import tcpiplib.prints
import gen.cli


def print_type_unknown(pkt):
    string = 'OpenFlow OFP_Type %s unknown \n'
    print string % (pkt.of_h['type'])


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
    for item in range(0,pad_len-1):
        string += '0'
    return string


def print_of_hello(msg):
    print 'OpenFlow Hello'


def print_of_error(msg):
    nCode, tCode = of10.dissector.get_ofp_error(msg.type, msg.code)
    print ('OpenFlow Error - Type: %s Code: %s' % (red(nCode), red(tCode)))
    hexdump(msg.data)


def print_of_feature_req(msg):
    print 'OpenFlow Feature Request'


def print_of_getconfig_req(msg):
    print 'OpenFlow GetConfig Request'


def print_of_feature_res(msg):
    dpid = datapath_id(msg.datapath_id)
    print ('FeatureRes - datapath_id: %s n_buffers: %s n_tbls: %s, pad: %s'
           % (green(dpid), msg.n_buffers, msg.n_tbls, print_pad(msg.pad)))
    print ('FeatureRes - Capabilities:'),
    for i in msg.capabilities:
        print of10.dissector.get_feature_res_capabilities(i),
    print
    print ('FeatureRes - Actions:'),
    for i in msg.actions:
        print of10.dissector.get_feature_res_actions(i),
    print
    print_of_ports(msg.ports)


def _dont_print_0(printed):
    if printed is False:
        print '0',
    return False


def print_port_field(port_id, variable, name):
    port_id = '%s' % green(port_id)
    printed = False

    print ('Port_id: %s - %s:' % (port_id, name)),
    for i in variable:
        print of10.dissector.get_phy_feature(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print


def print_ofp_phy_port(port):
    port_id = '%s' % green(port.port_id)

    print ('Port_id: %s - hw_addr: %s name: %s' % (
           port_id, green(port.hw_addr), green(port.name)))

    print ('Port_id: %s - config:' % port_id),
    printed = False
    for i in port.config:
        print of10.dissector.get_phy_config(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print

    print ('Port_id: %s - state:' % port_id),
    for i in port.state:
        print of10.dissector.get_phy_state(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print

    # TODO: fix it
    print_port_field(port_id, port.curr, 'curr')
    print_port_field(port_id, port.advertised, 'advertised')
    print_port_field(port_id, port.supported, 'supported')
    print_port_field(port_id, port.peer, 'peer')


def print_of_ports(ports):
    if type(ports) is not list:
        print_ofp_phy_port(ports)
    else:
        for port in ports:
            print_ofp_phy_port(port)


def print_ofp_match(match):
    print 'Match -',
    # Collect all variables from class ofp_match
    # print those that are not 'None'
    for match_item in match.__dict__:
        match_item_value = match.__dict__[match_item]
        if match_item_value is not None:
             if match_item is 'dl_vlan':
                 match_item_value = of10.dissector.get_vlan(match_item_value)
             elif match_item is 'wildcards':
                 match_item_value = hex(match_item_value)
             elif match_item is 'dl_type':
                 match_item_value = tcpiplib.tcpip.get_ethertype(match_item_value)

             print ("%s: %s" % (match_item, green(match_item_value))),
    print


def print_ofp_body(msg):
    string = ('Body - Cookie: %s Command: %s Idle/Hard Timeouts: '
              '%s/%s\nBody - Priority: %s Buffer ID: %s Out Port: %s Flags: %s')
    command = green(of10.dissector.get_ofp_command(msg.command))
    flags = green(of10.dissector.get_ofp_flags(msg.flags))
    out_port = green(of10.dissector.get_phy_port_id(msg.out_port))

    print string % (msg.cookie, command, msg.idle_timeout, msg.hard_timeout,
                    green(msg.priority), msg.buffer_id, out_port, flags)


def print_ofp_flow_removed(msg):
    print_ofp_match(msg.match)

    string = ('Body - Cookie: %s Priority: %s Reason: %s Pad: %s\nBody - '
              'Duration Secs/NSecs: %s/%s Idle Timeout: %s Pad2/Pad3: %s/%s'
              ' Packet Count: %s Byte Count: %s')

    print string % (msg.cookie, msg.priority, red(msg.reason),
                    print_pad(msg.pad), msg.duration_sec, msg.duration_nsec,
                    msg.idle_timeout, print_pad(msg.pad2),
                    print_pad(msg.pad3), msg.packet_count, msg.byte_count)


def print_actions(actions):
    for action in actions:
        print_ofp_action(action.type, action.length, action.payload)


def print_ofp_action(action_type, length, payload):
    if action_type == 0:
        port, max_len = of10.parser.get_action(action_type, payload)

        port = of10.dissector.get_phy_port_id(port)
        print ('Action - Type: %s Length: %s Port: %s '
               'Max Length: %s' %
               (green('OUTPUT'), length, green(port), max_len))
        return 'output:' + port

    elif action_type == 1:
        vlan, pad = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s VLAN ID: %s Pad: %s' %
               (green('SetVLANID'), length, green(str(vlan)), print_pad(pad)))
        return 'mod_vlan_vid:' + str(vlan)

    elif action_type == 2:
        vlan_pc, pad = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s VLAN PCP: %s Pad: %s' %
               (green('SetVLANPCP'), length, green(str(vlan_pc)), print_pad(pad)))
        return 'mod_vlan_pcp:' + str(vlan_pc)

    elif action_type == 3:
        print ('Action - Type: %s Length: %s' %
               (green('StripVLAN'), length))
        return 'strip_vlan'

    elif action_type == 4:
        setDLSrc, pad = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s SetDLSrc: %s Pad: %s' %
               (green('SetDLSrc'), length, green(str(eth_addr(setDLSrc))),
                print_pad(pad)))
        return 'mod_dl_src:' + str(eth_addr(setDLSrc))

    elif action_type == 5:
        setDLDst, pad = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s SetDLDst: %s Pad: %s' %
               (green('SetDLDst'), length, green(str(eth_addr(setDLDst))),
                print_pad(pad)))
        return 'mod_dl_dst:' + str(eth_addr(setDLDst))

    elif action_type == 6:
        nw_addr = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s SetNWSrc: %s' %
               (green('SetNWSrc'), length, green(str(nw_addr))))
        return 'mod_nw_src:' + str(nw_addr)

    elif action_type == 7:
        nw_addr = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s SetNWDst: %s' %
               (green('SetNWDst'), length, green(str(nw_addr))))
        return 'mod_nw_src:' + str(nw_addr)

    elif action_type == 8:
        nw_tos, pad = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s SetNWTos: %s Pad: %s' %
               (green('SetNWTos'), length, green(str(nw_tos)), print_pad(pad)))
        return 'mod_nw_tos:' + str(nw_tos)

    elif action_type == 9:
        port, pad = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s SetTPSrc: %s Pad: %s' %
               (green('SetTPSrc'), length, green(str(port)), print_pad(pad)))
        return 'mod_tp_src:' + str(port)

    elif action_type == int('a', 16):
        port, pad = of10.parser.get_action(action_type, payload)
        print ('Action - Type: %s Length: %s SetTPDst: %s Pad: %s' %
               (green('SetTPDst'), length, green(str(port)), print_pad(pad)))
        return 'mod_tp_dst:' + str(port)

    elif action_type == int('b', 16):
        port, pad, queue_id = of10.parser.get_action(action_type, payload)
        print (('Action - Type: %s Length: %s Enqueue: %s Pad: %s'
                ' Queue: %s') %
               (green('Enqueue'), length, green(str(port)), print_pad(pad),
                green(str(queue_id))))
        return 'set_queue:' + str(queue_id)

    elif action_type == int('ffff', 16):
        vendor = of10.parser.get_action(action_type, payload)
        print ('Action - Type:  %s Length: %s Vendor: %s' %
               (green('VENDOR'), length, green(str(vendor))))
        return 'VendorType'

    else:
        return 'Error'


def get_command(command):
    commands = {0: 'add-flow', 1: 'mod-flows', 3: 'del-flows'}
    try:
        return commands[command]
    except KeyError:
        return 0


def get_flag(flag):
    flags = {0: '', 1: 'send_flow_rem', 2: 'check_overlap', 3: 'Emerg'}
    try:
        return flags[flag]
    except KeyError:
        return 0


def get_actions(action_type, action_length, payload):
    if action_type == 0:
        port, max_len = of10.parser.get_action(action_type, payload)
        return 'output:%s' % (port if port != 65533 else 'CONTROLLER')
    elif action_type == 1:
        vlan, pad = of10.parser.get_action(action_type, payload)
        return 'mod_vlan_vid:' + str(vlan)
    elif action_type == 2:
        vlan_pc, pad = of10.parser.get_action(action_type, payload)
        return 'mod_vlan_pcp:' + str(vlan_pc)
    elif action_type == 3:
        return 'strip_vlan'
    elif action_type == 4:
        setDLSrc, pad = of10.parser.get_action(action_type, payload)
        return 'mod_dl_src:' + str(eth_addr(setDLSrc))
    elif action_type == 5:
        setDLDst, pad = of10.parser.get_action(action_type, payload)
        return 'mod_dl_dst:' + str(eth_addr(setDLDst))
    elif action_type == 6:
        nw_addr = of10.parser.get_action(action_type, payload)
        return 'mod_nw_src:' + str(nw_addr)
    elif action_type == 7:
        nw_addr = of10.parser.get_action(action_type, payload)
        return 'mod_nw_src:' + str(nw_addr)
    elif action_type == 8:
        nw_tos, pad = of10.parser.get_action(action_type, payload)
        return 'mod_nw_tos:' + str(nw_tos)
    elif action_type == 9:
        port, pad = of10.parser.get_action(action_type, payload)
        return 'mod_tp_src:' + str(port)
    elif action_type == int('a', 16):
        port, pad = of10.parser.get_action(action_type, payload)
        return 'mod_tp_dst:' + str(port)
    elif action_type == int('b', 16):
        port, pad, queue_id = of10.parser.get_action(action_type, payload)
        return 'set_queue:' + str(queue_id)


def print_ofp_ovs(msg):

    '''
        If -o or --print-ovs is provided by user, print a ovs-ofctl add-dump
    '''
    if gen.cli.print_ovs is not True:
        return

    switch_ip = 'SWITCH_IP'
    switch_port = '6634'

    ofm = []
    ofactions = []

    ovs_command = get_command(msg.command)

    for K in msg.match.__dict__:
        if K != 'wildcards':
            if msg.match.__dict__[K] is not None:
                value = "%s=%s," % (K, msg.match.__dict__[K])
                ofm.append(value)

    matches = ''.join(ofm)

    if msg.command is not 3:
        for action in msg.actions:
                value = get_actions(action.type, action.length, action.payload)
                value = "%s," % (value)
                ofactions.append(value)

        flag = get_flag(msg.flags)
        print('ovs-ofctl %s tcp:%s:%s \"' % (ovs_command, switch_ip, switch_port)),
        if msg.flags != 0:
            print('%s,' % flag),
        if msg.priority != 32678:
            print('priority=%s,' % msg.priority),
        if msg.idle_timeout != 0:
            print('idle_timeout=%s,' % msg.idle_timeout),
        if msg.hard_timeout != 0:
            print('hard_timeout=%s,' % msg.hard_timeout),
        print('%s ' % matches),
        print('action=%s\"' % ''.join(ofactions))
    else:
        ovs_msg_del = 'ovs-ofctl %s tcp:%s:%s %s '
        print(ovs_msg_del % (ovs_command, switch_ip, switch_port, matches))


def print_of_FlowMod(msg):
    print_ofp_match(msg.match)
    print_ofp_body(msg)
    print_actions(msg.actions)
    print_ofp_ovs(msg)


def _print_portMod_config_mask(variable, name):

    print ('PortMod %s:' % name),
    printed = False
    for i in variable:
        print of10.dissector.get_phy_config(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print


def print_of_PortMod(msg):
    print ('PortMod Port_no: %s HW_Addr %s Pad: %s' %
           (msg.port_no, eth_addr(msg.hw_addr), print_pad(msg.pad)))
    _print_portMod_config_mask(msg.config, 'config')
    _print_portMod_config_mask(msg.mask, 'mask')
    _print_portMod_config_mask(msg.advertise, 'advertise')


def print_of_BarrierReq(msg):
    print 'OpenFlow Barrier Request'


def print_of_BarrierReply(msg):
    print 'OpenFlow Barrier Reply'


def print_of_vendor(msg):
    vendor = of10.dissector.get_ofp_vendor(msg.vendor)
    print ('OpenFlow Vendor: %s' % vendor)


def print_ofp_statReq(msg):
    if msg.stat_type == 0:
        print_ofp_statReqDesc(msg)
    elif msg.stat_type == 1 or msg.type == 2:
        print_ofp_statReqFlowAggregate(msg)
    elif msg.stat_type == 3:
        print_ofp_statReqTable(msg)
    elif msg.stat_type == 4:
        print_ofp_statReqPort(msg)
    elif msg.stat_type == 5:
        print_ofp_statReqQueue(msg)
    elif msg.stat_type == 65535:
        print_ofp_statReqVendor(msg)


def print_ofp_statReqDesc(msg):
    print 'StatReq Type: Description(%s)' % msg.stat_type


def print_ofp_statReqFlowAggregate(msg):
    if msg.stat_type == 1:
        type_name = 'Flow'
    else:
        type_name = 'Aggregate'
    print ('StatReq Type: %s(%s)' % (type_name, msg.stat_type))
    print_ofp_match(msg.stats.match)
    out_port = of10.dissector.get_phy_port_id(msg.stats.out_port)
    print ('StatReq Table_id: %s Pad: %s Out_Port: %s' % (msg.stats.table_id,
           print_pad(msg.stats.pad), out_port))


def print_ofp_statReqTable(msg):
    print 'StatReq Type: Table(%s)' % msg.stat_type


def print_ofp_statReqPort(msg):
    port_number = of10.dissector.get_phy_port_id(msg.stats.port_number)
    print ('StatReq Type: Port(%s): Port_Number: %s Pad: %s' %
           (msg.stat_type, green(port_number), print_pad(msg.stats.pad)))


def print_ofp_statReqQueue(msg):
    port_number = of10.dissector.get_phy_port_id(msg.stats.port_number)
    print ('StatReq Type: Queue(%s): Port_Number: %s Pad: %s Queue_id: %s' %
           (msg.stat_type, green(port_number), print_pad(msg.stats.pad),
            msg.stats.queue_id))


def print_ofp_statReqVendor(msg):
    vendor = of10.dissector.get_ofp_vendor(msg.stats.vendor_id)
    print ('StatReq Type: Vendor(%s): Vendor_ID: %s' % (msg.stat_type,
           vendor))


def print_ofp_statRes(msg):
    if msg.stat_type == 0:
        print_ofp_statResDesc(msg)
    elif msg.stat_type == 1:
        print_ofp_statResFlowArray(msg)
    elif msg.stat_type == 2:
        print_ofp_statResAggregate(msg)
    elif msg.stat_type == 3:
        print_ofp_statResTableArray(msg)
    elif msg.stat_type == 4:
        print_ofp_statResPortArray(msg)
    elif msg.stat_type == 5:
        print_ofp_statResQueueArray(msg)
    elif msg.stat_type == 65535:
        print_ofp_statResVendor(msg)


def print_ofp_statResDesc(msg):
    print ('StatRes Type: Description(%s)' % (msg.stat_type))
    print ('StatRes mfr_desc: %s' % (msg.stats.mfr_desc))
    print ('StatRes hw_desc: %s' % (msg.stats.hw_desc))
    print ('StatRes sw_desc: %s' % (msg.stats.sw_desc))
    print ('StatRes serial_num: %s' % (msg.stats.serial_num))
    print ('StatRes dp_desc: %s' % (msg.stats.dp_desc))


def print_ofp_statResFlowArray(msg):
    if len(msg.stats.flows) == 0:
        print ('StatRes Type: Flow(1)\nNo Flows')
        return

    for flow in msg.stats.flows:
        print_ofp_statResFlow(flow)


def print_ofp_statResFlow(flow):
    print ('StatRes Type: Flow(1)')
    print ('StatRes Length: %s Table_id: %s Pad: %s ' %
           (flow.length, flow.table_id, print_pad(flow.pad)))
    print ('StatRes'),
    print_ofp_match(flow.match)
    print ('StatRes duration_sec: %s, duration_nsec: %s, priority: %s,'
           ' idle_timeout: %s, hard_timeout: %s, pad: %s, cookie: %s,'
           ' packet_count: %s, byte_count: %s' %
           (flow.duration_sec, flow.duration_nsec,
            flow.priority, flow.idle_timeout,
            flow.hard_timeout, print_pad(flow.pad),
            flow.cookie,
            flow.packet_count, flow.byte_count))
    print ('StatRes'),
    print_actions(flow.actions)


def print_ofp_statResAggregate(msg):
    print ('StatRes Type: Aggregate(2)')
    print ('StatRes packet_count: %s, byte_count: %s flow_count: %s '
           'pad: %s' %
           (msg.stats.packet_count, msg.stats.byte_count,
            msg.stats.flow_count, print_pad(msg.stats.pad)))


def print_ofp_statResTableArray(msg):
    if len(msg.stats.tables) == 0:
        print ('StatRes Type: Table(3)\nNo Tables')
        return

    print ('StatRes Type: Table(3)')
    for table in msg.stats.tables:
        print_ofp_statResTable(table)


def print_ofp_statResTable(table):
    print ('StatRes table_id: %s, pad: %s, name: "%s", wildcards: %s, '
           'max_entries: %s, active_count: %s, lookup_count: %s, '
           'matched_count: %s' %
           (table.table_id, print_pad(table.pad), table.name, hex(table.wildcards),
            table.max_entries, table.active_count,
            table.lookup_count, table.matched_count))


def print_ofp_statResPortArray(msg):
     if len(msg.stats.ports) == 0:
        print ('StatRes Type: Port(4)\nNo Ports')
        return
     for port in msg.stats.ports:
        print_ofp_statResPort(port)


def print_ofp_statResPort(port):
    print ('StatRes Type: Port(4)')
    print ('StatRes port_number: %s rx_packets: %s rx_bytes: %s rx_errors: %s'
           ' rx_crc_err: %s rx_dropped: %s rx_over_err: %s rx_frame_err: %s\n'
           'StatRes port_number: %s tx_packets: %s tx_bytes: %s tx_errors: %s'
           ' tx_dropped: %s collisions: %s pad: %s' %
           (red(port.port_number), port.rx_packets,
            port.rx_bytes, port.rx_errors, port.rx_crc_err,
            port.rx_dropped, port.rx_over_err,
            port.rx_frame_err, red(port.port_number),
            port.tx_packets, port.tx_bytes, port.tx_errors,
            port.tx_dropped, port.collisions, print_pad(port.pad)))


def print_ofp_statResQueueArray(msg):
    if len(msg.stats.queues) == 0:
        print 'StatRes Type: Queue(5)\nNo Queues'
        return

    for queue in msg.queues:
        print_ofp_statResQueue(queue)


def print_ofp_statResQueue(queue):
    print 'StatRes Type: Queue(5)'
    print ('StatRes queue_id: %s length: %s pad: %s'
           ' tx_bytes: %s tx_packets: %s tx_errors: %s' %
           (queue.queue_id, queue.length, print_pad(queue.pad),
            queue.tx_bytes, queue.tx_packets, queue.tx_errors))


def print_ofp_statResVendor(msg):
    print ('StatRes Type: Vendor(%s)' % (hex(65535)))
    print ('StatRes vendor_id: %s' % (msg.stats.vendor_id))
    print_ofp_statResVendorData(msg.stats.data)


def print_ofp_statResVendorData(data):
    print ('StatRes Vendor Data: ')
    hexdump(data)


def print_ofp_getConfigRes(msg):
    print ('OpenFlow GetConfigRes - Flag: %s Miss_send_len: %s' %
           (msg.flags, msg.miss_send_len))


def print_ofp_setConfig(msg):
    print ('OpenFlow SetConfig - Flag: %s Miss_send_len: %s' %
           (msg.flags, msg.miss_send_len))


def print_of_echoreq(msg):
    print 'OpenFlow Echo Request'


def print_of_echores(msg):
    print 'OpenFlow Echo Reply'


def print_portStatus(msg):
    print ('OpenFlow PortStatus - Reason: %s Pad: %s' % (msg.reason,
                                                         print_pad(msg.pad)))
    print_of_ports(msg.desc)


def print_packetInOut_layer2(of_xid, eth):
    print ('%s' % of_xid),
    tcpiplib.prints.print_layer2(eth)


def print_packetInOut_vlan(of_xid, vlan):
    print ('%s Ethernet:' % of_xid),
    tcpiplib.prints.print_vlan(vlan)


def print_of_packetIn(msg):
    print ('PacketIn: buffer_id: %s total_len: %s in_port: %s reason: %s '
           'pad: %s' %
           (hex(msg.buffer_id), msg.total_len, green(msg.in_port),
            green(msg.reason), print_pad(msg.pad)))
    print_data(msg.data)


def print_of_packetOut(msg):
    print ('PacketOut: buffer_id: %s in_port: %s actions_len: %s' %
           (hex(msg.buffer_id),
            green(of10.dissector.get_phy_port_id(msg.in_port)),
            msg.actions_len))
    if msg.actions_len is not 0:
        print_actions(msg.actions)
        print_data(msg.data)


def print_data(data):
    """
        Print msg.data from both PacketIn and Packetout
        Args:
            data: msg.data - array of protocols
    """
    next_protocol = '0x0000'
    eth = data.pop(0)
    tcpiplib.prints.print_layer2(eth)
    next_protocol = eth.protocol
    if next_protocol in [33024]:
        vlan = data.pop(0)
        tcpiplib.prints.print_vlan(vlan)
        next_protocol = vlan.protocol

    if next_protocol in [35020, 35138]:
        lldp = data.pop(0)
        tcpiplib.prints.print_lldp(lldp)
    elif next_protocol in [34998]:
        print 'OESS FVD'
    elif next_protocol in [2048]:
        ip = data.pop(0)
        tcpiplib.prints.print_layer3(ip)
        if ip.protocol is 6:
            tcp = data.pop(0)
            tcpiplib.prints.print_tcp(tcp)
    elif next_protocol in [2054]:
        arp = data.pop(0)
        tcpiplib.prints.print_arp(arp)


def print_queueReq(msg):
    print ('QueueGetConfigReq Port: %s Pad: %s' %
           (msg.port, print_pad(msg.pad)))


def print_queueRes(msg):
    print ('QueueGetConfigRes Port: %s Pad: %s' %
           (msg.port, print_pad(msg.pad)))
    if len(msg.queues) == 0:
        print 'QueueGetConfigRes: No Queues'
        return
    for queue in msg.queues:
        print_queueRes_queue(queue)


def print_queueRes_queue(queue):
    print ('Queue_ID: %s Length: %s Pad: %s' %
           (queue.queue_id, queue.length, print_pad(queue.pad)))
    if len(queue.properties) == 0:
        print 'QueueGetConfigRes: No Properties'
        return
    for property in queue.properties:
        print_queueRes_properties(property)


def print_queueRes_properties(qproperty):
    print ('Property: %s Length: %s Pad: %s' %
           (qproperty.property, qproperty.length, print_pad(qproperty.pad)))
    print_queueRes_prop_payload(qproperty.payload)


def print_queueRes_prop_payload(payload):
    print ('Payload: Rate %s Pad: %s' %
           (payload.rate, print_pad(payload.pad)))
