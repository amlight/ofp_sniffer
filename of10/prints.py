'''
    Prints for OpenFlow 1.0 only
'''
import of10.dissector
import of10.parser
import gen.prints
import gen.packet
import gen.tcpip


def red(string):
    return gen.prints.red(string)


def green(string):
    return gen.prints.green(string)


def eth_addr(string):
    return gen.prints.eth_addr(string)


def datapath_id(string):
    return gen.prints.datapath_id(string)


def print_layer2(pkt):
    gen.prints.print_layer2(pkt.l2)


def print_layer2_pktIn(pkt):
    gen.prints.print_layer2(pkt.of_body['print_layer2_pktIn'])


def print_tcp(pkt):
    gen.prints.print_tcp(pkt.of_body['print_tcp'])


def print_layer3(pkt):
    gen.prints.print_layer3(pkt.of_body['print_layer3'])


def print_lldp(pkt):
    gen.prints.print_lldp(pkt)


def print_arp(pkt):
    gen.prints.print_arp(pkt.of_body['print_arp'])


def print_vlan(pkt):
    gen.prints.print_vlan(pkt.of_body['print_vlan'])


def print_string(pkt):
    print pkt.of_body['print_string']['message']


def print_type_unknown(pkt):
    string = 'OpenFlow OFP_Type %s unknown \n'
    print string % (pkt.of_h['type'])


def print_of_hello(msg):
    print 'OpenFlow Hello'


def print_of_error(msg):
    nCode, tCode = of10.dissector.get_ofp_error(msg.type, msg.code)
    print ('OpenFlow Error - Type: %s Code: %s' % (red(nCode), red(tCode)))


def print_of_feature_req(msg):
    print 'OpenFlow Feature Request'


def print_of_getconfig_req(msg):
    print 'OpenFlow GetConfig Request'


def print_of_feature_res(msg):
    dpid = datapath_id(msg.datapath_id)
    print ('FeatureRes - datapath_id: %s n_buffers: %s n_tbls: %s, pad: %s'
           % (green(dpid), msg.n_buffers, msg.n_tbls, msg.pad))
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

    print ('Port_id: %s - %s curr:' % (port_id, name)),
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

    # fix it
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
                 match_item_value = gen.tcpip.get_ethertype(match_item_value)

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

    print string % (msg.cookie, msg.priority, red(msg.reason), msg.pad,
                    msg.duration_sec, msg.duration_nsec, msg.idle_timeout,
                    msg.pad2, msg.pad3, msg.packet_count, msg.byte_count)


def print_actions(msg):
    for action in msg.actions:
        print_ofp_action(action.type, action.length, action.payload)


def print_ofp_action(action_type, length, payload):
    if action_type == 0:
        port, max_len = of10.parser.get_action(action_type, length, payload)

        port = of10.dissector.get_phy_port_id(port)
        print ('Action - Type: %s Length: %s Port: %s '
               'Max Length: %s' %
               (green('OUTPUT'), length, green(port), max_len))
        return 'output:' + port

    elif action_type == 1:
        vlan, pad = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s VLAN ID: %s Pad: %s' %
               (green('SetVLANID'), length, green(str(vlan)), pad))
        return 'mod_vlan_vid:' + str(vlan)

    elif action_type == 2:
        vlan_pc, pad = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s VLAN PCP: %s Pad: %s' %
               (green('SetVLANPCP'), length, green(str(vlan_pc)), pad))
        return 'mod_vlan_pcp:' + str(vlan_pc)

    elif action_type == 3:
        print ('Action - Type: %s Length: %s' %
               (green('StripVLAN'), length))
        return 'strip_vlan'

    elif action_type == 4:
        setDLSrc, pad = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s SetDLSrc: %s Pad: %s' %
               (green('SetDLSrc'), length, green(str(eth_addr(setDLSrc))),
                pad))
        return 'mod_dl_src:' + str(eth_addr(setDLSrc))

    elif action_type == 5:
        setDLDst, pad = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s SetDLDst: %s Pad: %s' %
               (green('SetDLDst'), length, green(str(eth_addr(setDLDst))),
                pad))
        return 'mod_dl_dst:' + str(eth_addr(setDLDst))

    elif action_type == 6:
        nw_addr = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s SetNWSrc: %s' %
               (green('SetNWSrc'), length, green(str(nw_addr))))
        return 'mod_nw_src:' + str(nw_addr)

    elif action_type == 7:
        nw_addr = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s SetNWDst: %s' %
               (green('SetNWDst'), length, green(str(nw_addr))))
        return 'mod_nw_src:' + str(nw_addr)

    elif action_type == 8:
        nw_tos, pad = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s SetNWTos: %s Pad: %s' %
               (green('SetNWTos'), length, green(str(nw_tos)), pad))
        return 'mod_nw_tos:' + str(nw_tos)

    elif action_type == 9:
        port, pad = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s SetTPSrc: %s Pad: %s' %
               (green('SetTPSrc'), length, green(str(port)), pad))
        return 'mod_tp_src:' + str(port)

    elif action_type == int('a', 16):
        port, pad = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type: %s Length: %s SetTPDst: %s Pad: %s' %
               (green('SetTPDst'), length, green(str(port)), pad))
        return 'mod_tp_dst:' + str(port)

    elif action_type == int('b', 16):
        port, pad, queue_id = of10.parser.get_action(action_type, length,
                                                     payload)
        print (('Action - Type: %s Length: %s Enqueue: %s Pad: %s'
                ' Queue: %s') %
               (green('Enqueue'), length, green(str(port)), pad,
                green(str(queue_id))))
        return 'set_queue:' + str(queue_id)

    elif action_type == int('ffff', 16):
        vendor = of10.parser.get_action(action_type, length, payload)
        print ('Action - Type:  %s Length: %s Vendor: %s' %
               (green('VENDOR'), length, green(str(vendor))))
        return 'VendorType'

    else:
        return 'Error'


def print_ofp_ovs(print_options, ofmatch, ofactions, ovs_command, prio):

    '''
        If -o or --print-ovs is provided by user, print a ovs-ofctl add-dump
    '''
    switch_ip = print_options['device_ip']
    switch_port = print_options['device_port']

    ofm = []

    for K in ofmatch:
        if K != 'wildcards':
            value = "%s=%s," % (K, ofmatch[K])
            ofm.append(value)

    matches = ''.join(ofm)
    actions = ''.join(ofactions)

    print ('ovs-ofctl %s tcp:%s:%s "priority=%s %s %s"' %
           (ovs_command, switch_ip, switch_port, prio, matches,
            (actions if ovs_command != 'del-flows' else '')))
    return


def print_of_FlowMod(msg):
    print_ofp_match(msg.match)
    print_ofp_body(msg)
    print_actions(msg)


def _print_portMod_config_mask(variable, name):

    print ('PortMod %s:' % (name)),
    printed = False
    for i in variable:
        print of10.dissector.get_phy_config(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print


def print_of_PortMod(msg):
    print ('PortMod Port_no: %s HW_Addr %s Pad: %s' %
           (msg.port_no, eth_addr(msg.hw_addr), msg.pad))
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
    print ('StatReq Table_id: %s Pad: %d Out_Port: %s' % (msg.stats.table_id,
           msg.stats.pad, out_port))


def print_ofp_statReqTable(msg):
    print 'StatReq Type: Table(%s)' % msg.stat_type


def print_ofp_statReqPort(msg):
    port_number = of10.dissector.get_phy_port_id(msg.stats.port_number)
    print ('StatReq Type: Port(%s): Port_Number: %s Pad: %s' %
           (msg.stat_type, green(port_number), msg.stats.pad))


def print_ofp_statReqQueue(msg):
    port_number = of10.dissector.get_phy_port_id(msg.stats.port_number)
    print ('StatReq Type: Queue(%s): Port_Number: %s Pad: %s Queue_id: %s' %
           (msg.stat_type, green(port_number), msg.stats.pad, msg.stats.queue_id))


def print_ofp_statReqVendor(msg):
    print ('StatReq Type: Vendor(%s): Vendor_ID: %s' % (msg.stat_type,
           msg.stats.vendor_id))


def print_ofp_statResDesc(msg):
    stats = pkt.of_body['print_ofp_statResDesc']
    print ('StatRes Type: Description(%s)' % (stats['type']))
    print ('StatRes mfr_desc: %s' % (stats['mfr_desc']))
    print ('StatRes hw_desc: %s' % (stats['hw_desc']))
    print ('StatRes sw_desc: %s' % (stats['sw_desc']))
    print ('StatRes serial_num: %s' % (stats['serial_num']))
    print ('StatRes dp_desc: %s' % (stats['dp_desc']))


def print_ofp_statResFlowArray(msg):
    flows = pkt.of_body['print_ofp_statResFlowArray']
    if len(flows) == 0:
        print ('StatRes Type: Flow(1)\nNo Flows')
        return

    for flow_stats in flows:
        print_ofp_statResFlow(pkt, flow_stats)


def print_ofp_statResFlow(msg, stats):
    stat_type = stats['type']
    res_flow = stats['res_flow']
    print ('StatRes Type: Flow(%s)' % (stat_type))
    print ('StatRes Length: %s Table_id: %s Pad: %s ' %
           (res_flow['length'], res_flow['table_id'], res_flow['pad']))
    print ('StatRes'),
    pkt.of_body['print_ofp_match'] = stats['match']
    print_ofp_match(pkt)
    print ('StatRes duration_sec: %s, duration_nsec: %s, priority: %s,'
           ' idle_timeout: %s, hard_timeout: %s, pad: %s, cookie: %s,'
           ' packet_count: %s, byte_count: %s' %
           (res_flow['duration_sec'], res_flow['duration_nsec'],
            res_flow['priority'], res_flow['idle_timeout'],
            res_flow['hard_timeout'], res_flow['pad'],
            res_flow['cookie'],
            res_flow['packet_count'], res_flow['byte_count']))
    pkt.of_body['print_actions'] = stats['print_actions']
    print_actions(pkt)


def print_ofp_statResAggregate(pkt):
    res_flow = pkt.of_body['print_ofp_statResAggregate']
    print ('StatRes Type: Aggregate(%s)' % (res_flow['type']))
    print ('StatRes packet_count: %s, byte_count: %s flow_count: %s '
           'pad: %s' %
           (res_flow['packet_count'], res_flow['byte_count'],
            res_flow['flow_count'], res_flow['pad']))


def print_ofp_statResTable(pkt):
    res_flow = pkt.of_body['print_ofp_statResTable']
    print ('StatRes Type: Table(%s)' % (res_flow['type']))
    print ('StatRes table_id: %s, pad: %s, name: "%s", wildcards: %s, '
           'max_entries: %s, active_count: %s, lookup_count: %s, '
           'matched_count: %s' %
           (res_flow['table_id'], res_flow['pad'],
            res_flow['name'], hex(res_flow['wildcards']),
            res_flow['max_entries'], res_flow['active_count'],
            res_flow['lookup_count'], res_flow['matched_count']))


def print_ofp_statResPortArray(pkt):
    for port_stats in pkt.of_body['print_ofp_statResPortArray']:
        print_ofp_statResPort(port_stats)


def print_ofp_statResPort(port):
    print ('StatRes Type: Port(%s)' % (port['type']))
    print ('StatRes port_no: %s rx_packets: %s rx_bytes: %s rx_errors: %s'
           ' rx_crc_err: %s rx_dropped: %s rx_over_err: %s rx_frame_err: %s\n'
           'StatRes port_no: %s tx_packets: %s tx_bytes: %s tx_errors: %s'
           ' tx_dropped: %s collisions: %s pad: %s' %
           (red(port['port_no']), port['rx_packets'],
            port['rx_bytes'], port['rx_errors'], port['rx_crc_err'],
            port['rx_dropped'], port['rx_over_err'],
            port['rx_frame_err'], red(port['port_no']),
            port['tx_packets'], port['tx_bytes'], port['tx_errors'],
            port['tx_dropped'], port['collisions'], port['pad']))


def print_ofp_statResQueueArray(pkt):
    queues = pkt.of_body['print_ofp_statResQueueArray']
    if len(queues) == 0:
        print 'StatRes Type: Queue(5)\nNo Queues'
        return

    for queue_stats in queues:
        print_ofp_statResQueue(queue_stats)


def print_ofp_statResQueue(queue):
    print ('StatRes Type: Queue(%s)' % (queue['type']))
    print ('StatRes queue_id: %s length: %s pad: %s'
           ' tx_bytes: %s tx_packets: %s tx_errors: %s' %
           (queue['queue_id'], queue['length'], queue['pad'],
            queue['tx_bytes'], queue['tx_packets'],
            queue['tx_errors']))


def print_ofp_statResVendor(pkt):
    vendor = pkt.of_body['print_ofp_statResVendor']
    print ('StatRes Type: Vendor(%s)' % (vendor['type']))
    print ('StatRes vendor_id: %s' % (vendor['vendor_id']))


def print_ofp_statResVendorData(pkt):
    data = pkt.of_body['print_ofp_statResVendorData']
    # print 'StatRes Vendor Data: %s' % (data)
    print ('StatRes Vendor Data: ')
    import hexdump
    hexdump.hexdump(data)


def print_ofp_getConfigRes(msg):
    print ('OpenFlow GetConfigRes - Flag: %s Miss_send_len: %s' %
           (msg.flag, msg.miss_send_len))


def print_ofp_setConfig(msg):
    print ('OpenFlow SetConfig - Flag: %s Miss_send_len: %s' %
           (msg.flags, msg.miss_send_len))


def print_of_echoreq(msg):
    # print data
    print 'OpenFlow Echo Request'


def print_of_echores(msg):
    # print data
    print 'OpenFlow Echo Reply'


def print_portStatus(msg):
    print ('OpenFlow PortStatus - Reason: %s Pad: %s' % (msg.reason, msg.pad))
    print_of_ports(msg.desc)


def print_packetInOut_layer2(of_xid, eth):
    print ('%s' % of_xid),
    gen.prints.print_layer2(eth)


def print_packetInOut_vlan(of_xid, vlan):
    print ('%s Ethernet:' % of_xid),
    gen.prints.print_vlan(vlan)


def print_data(data):
    # what to do with data?
    pass


def print_of_packetIn(msg):
    print ('PacketIn: buffer_id: %s total_len: %s in_port: %s reason: %s '
           'pad: %s' %
           (hex(msg.buffer_id), msg.total_len, green(msg.in_port), green(msg.reason),
            msg.pad))
    print_data(msg.data)


def print_of_packetOut(msg):
    print ('PacketOut: buffer_id: %s in_port: %s actions_len: %s' %
           (hex(msg.buffer_id), green(of10.dissector.get_phy_port_id(msg.in_port)),
            msg.actions_len))
    print_actions(msg)
    # print_data(msg.data)


def print_queueReq(pkt):
    queueConfReq = pkt.of_body['print_queueReq']
    print ('QueueGetConfigReq Port: %s Pad: %s' %
           (queueConfReq['port'], queueConfReq['pad']))


def print_queueRes(pkt):
    queueConfRes = pkt.of_body['print_queueRes']
    print ('QueueGetConfigRes Port: %s Pad: %s' %
           (queueConfRes['port'], queueConfRes['pad']))


def print_queueRes_queues(of_xid, queues):
    print ('%s Queue_ID: %s Length: %s Pad: %s' %
           (of_xid, queues['queue_id'], queues['length'], queues['pad']))


def print_queueRes_properties(of_xid, properties):
    print ('%s Property: %s Length: %s Pad: %s Rate: %s Pad: %s' %
           (of_xid, properties['type'], properties['length'], properties['pad'],
            properties['rate'], properties['pad2']))


def print_body(pkt):
    for f in pkt.printing_seq:
        eval(f)(pkt)
