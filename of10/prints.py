'''
    Prints for OpenFlow 1.0 only
'''

import of10.dissector
import of10.parser
import gen.prints
import gen.packet


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


def print_lldp(pkt):
    gen.prints.print_lldp(pkt)


def print_arp(pkt):
    gen.prints.print_arp(pkt.of_body['print_arp'])


def print_type_unknown(pkt):
    string = '%s OpenFlow OFP_Type %s unknown \n'
    print string % (pkt.of_h['xid'], pkt.of_h['type'])


def print_of_hello(pkt):
    print 'OpenFlow Hello'


def print_of_error(pkt):
    error = pkt.of_body['print_of_error']
    nCode, tCode = of10.dissector.get_ofp_error(error['type'], error['code'])
    print ('OpenFlow Error - Type: %s Code: %s' % (red(nCode), red(tCode)))


def print_of_feature_req(pkt):
    print 'OpenFlow Feature Request'


def print_of_getconfig_req(of_xid):
    print '%s OpenFlow GetConfig Request' % of_xid


def print_of_feature_res(of_xid, f_res):
    print '%s OpenFlow Feature Reply' % of_xid
    dpid = datapath_id(f_res['datapath_id'])
    print ('%s FeatureRes - datapath_id: %s n_buffers: %s n_tbls: %s, pad: %s'
           % (of_xid, green(dpid), f_res['n_buffers'], f_res['n_tbls'],
              f_res['pad']))


def print_of_feature_res_caps_and_actions(of_xid, caps, actions):
    print ('%s FeatureRes - Capabilities:' % of_xid),
    for i in caps:
        print of10.dissector.get_feature_res_capabilities(i),
    print
    print ('%s FeatureRes - Actions:' % of_xid),
    for i in actions:
        print of10.dissector.get_feature_res_actions(i),
    print


def _dont_print_0(printed):
    if printed is False:
        print '0',
    return False


def print_of_feature_res_ports(of_xid, ports):
    print ('%s FeatureRes - port_id: %s hw_addr: %s name: %s' % (of_xid,
           green(ports['port_id']), green(ports['hw_addr']),
           green(ports['name'])))
    print ('%s FeatureRes - config:' % of_xid),
    printed = False
    for i in ports['config']:
        print of10.dissector.get_phy_config(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print
    print ('%s FeatureRes - state:' % of_xid),
    for i in ports['state']:
        print of10.dissector.get_phy_state(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print
    print ('%s FeatureRes - curr:' % of_xid),
    for i in ports['curr']:
        print of10.dissector.get_phy_feature(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print
    print ('%s FeatureRes - advertised:' % of_xid),
    for i in ports['advertised']:
        print of10.dissector.get_phy_feature(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print
    print ('%s FeatureRes - supported:' % of_xid),
    for i in ports['supported']:
        print of10.dissector.get_phy_feature(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print
    print ('%s FeatureRes - peer:' % of_xid),
    for i in ports['peer']:
        print of10.dissector.get_phy_feature(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print


def print_ofp_match(xid, ofmatch):
    if xid == '':
        print 'OpenFlow Match -',
    else:
        print ('%s OpenFlow Match -' % (xid)),
    for K in ofmatch:
        print ("%s: %s" % (K, green(ofmatch[K]))),
    print


def print_ofp_body(xid, ofbody):
    string = ('%s OpenFlow Body - Cookie: %s Command: %s Idle/Hard Timeouts: '
              '%s/%s Priority: %s Buffer ID: %s Out Port: %s Flags: %s')
    command = green(of10.dissector.get_ofp_command(ofbody['command']))
    flags = green(of10.dissector.get_ofp_flags(ofbody['flags']))

    print string % (xid, ofbody['cookie'], command, ofbody['idle_timeout'],
                    ofbody['hard_timeout'], ofbody['priority'],
                    ofbody['buffer_id'], ofbody['out_port'], flags)


def print_ofp_flow_removed(xid, ofrem):
    string = ('%s OpenFlow Body - Cookie: %s Priority: %s Reason: %s Pad: %s '
              'Duration Secs/NSecs: %s/%s Idle Timeout: %s Pad2/Pad3: %s/%s'
              ' Packet Count: %s Byte Count: %s')

    print string % (xid, ofrem['cookie'], ofrem['priority'],
                    red(ofrem['reason']), ofrem['pad'], ofrem['duration_sec'],
                    ofrem['duration_nsec'], ofrem['idle_timeout'],
                    ofrem['pad2'], ofrem['pad3'], ofrem['packet_count'],
                    ofrem['byte_count'])


def print_ofp_action(action_type, length, payload):
    if action_type == 0:
        port, max_len = of10.parser.get_action(action_type, length, payload)

        port = of10.dissector.get_phy_port_id(port)
        print ('OpenFlow Action - Type: %s Length: %s Port: %s '
               'Max Length: %s' %
               (green('OUTPUT'), length, green(port), max_len))
        return 'output:' + port

    elif action_type == 1:
        vlan, pad = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s VLAN ID: %s Pad: %s' %
               (green('SetVLANID'), length, green(str(vlan)), pad))
        return 'mod_vlan_vid:' + str(vlan)

    elif action_type == 2:
        vlan_pc, pad = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s VLAN PCP: %s Pad: %s' %
               (green('SetVLANPCP'), length, green(str(vlan_pc)), pad))
        return 'mod_vlan_pcp:' + str(vlan_pc)

    elif action_type == 3:
        print ('OpenFlow Action - Type: %s Length: %s' %
               (green('StripVLAN'), length))
        return 'strip_vlan'

    elif action_type == 4:
        setDLSrc, pad = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s SetDLSrc: %s Pad: %s' %
               (green('SetDLSrc'), length, green(str(eth_addr(setDLSrc))),
                pad))
        return 'mod_dl_src:' + str(eth_addr(setDLSrc))

    elif action_type == 5:
        setDLDst, pad = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s SetDLDst: %s Pad: %s' %
               (green('SetDLDst'), length, green(str(eth_addr(setDLDst))),
                pad))
        return 'mod_dl_dst:' + str(eth_addr(setDLDst))

    elif action_type == 6:
        nw_addr = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s SetNWSrc: %s' %
               (green('SetNWSrc'), length, green(str(nw_addr))))
        return 'mod_nw_src:' + str(nw_addr)

    elif action_type == 7:
        nw_addr = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s SetNWDst: %s' %
               (green('SetNWDst'), length, green(str(nw_addr))))
        return 'mod_nw_src:' + str(nw_addr)

    elif action_type == 8:
        nw_tos, pad = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s SetNWTos: %s Pad: %s' %
               (green('SetNWTos'), length, green(str(nw_tos)), pad))
        return 'mod_nw_tos:' + str(nw_tos)

    elif action_type == 9:
        port, pad = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s SetTPSrc: %s Pad: %s' %
               (green('SetTPSrc'), length, green(str(port)), pad))
        return 'mod_tp_src:' + str(port)

    elif action_type == int('a', 16):
        port, pad = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type: %s Length: %s SetTPDst: %s Pad: %s' %
               (green('SetTPDst'), length, green(str(port)), pad))
        return 'mod_tp_dst:' + str(port)

    elif action_type == int('b', 16):
        port, pad, queue_id = of10.parser.get_action(action_type, length,
                                                     payload)
        print (('OpenFlow Action - Type: %s Length: %s Enqueue: %s Pad: %s'
                ' Queue: %s') %
               (green('Enqueue'), length, green(str(port)), pad,
                green(str(queue_id))))
        return 'set_queue:' + str(queue_id)

    elif action_type == int('ffff', 16):
        vendor = of10.parser.get_action(action_type, length, payload)
        print ('OpenFlow Action - Type:  %s Length: %s Vendor: %s' %
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


def _print_portMod_config_mask(of_xid, array, name):
    print ('%s PortMod %s:' % (of_xid, name)),
    printed = False
    for i in array[name]:
        print of10.dissector.get_phy_config(i),
        printed = True
    else:
        printed = _dont_print_0(printed)
    print


def print_PortMod(of_xid, portMod):
    print ('%s PortMod Port: %s HW Addr %s Pad: %s' %
           (of_xid, portMod['port'], eth_addr(portMod['hw_addr']),
            portMod['pad']))
    _print_portMod_config_mask(of_xid, portMod, 'config')
    _print_portMod_config_mask(of_xid, portMod, 'mask')
    _print_portMod_config_mask(of_xid, portMod, 'advertise')


def print_of_BarrierReq(pkt):
    print 'OpenFlow Barrier Request'


def print_of_BarrierReply(pkt):
    print 'OpenFlow Barrier Reply'


def print_of_vendor(of_vendor, of_xid):
    vendor = of10.dissector.get_ofp_vendor(of_vendor)
    print ('%s OpenFlow Vendor: %s' % (of_xid, vendor))


def print_ofp_statReqDesc(of_xid, stat_type):
    print ('%s StatReq Type: Description(%s)' % (of_xid, stat_type))


def print_ofp_statReqFlowAggregate(of_xid, stat_type, of_match, table_id, pad,
                                   out_port):
    if stat_type == 1:
        type_name = 'Flow'
    else:
        type_name = 'Aggregate'

    print ('%s StatReq Type: %s(%s)' % (of_xid, type_name, stat_type))
    print_ofp_match(of_xid, of_match)
    print ('%s StatReq Table_id: %s Pad: %d Out_Port: %s' % (of_xid, table_id,
           pad, out_port))


def print_ofp_statReqTable(of_xid, stat_type):
    print ('%s StatReq Type: Table(%s)' % (of_xid, stat_type))


def print_ofp_statReqPort(of_xid, stat_type, port_number, pad):
    print ('%s StatReq Type: Port(%s): Port_Number: %s Pad: %s' % (of_xid,
           stat_type, green(port_number), pad))


def print_ofp_statReqQueue(of_xid, stat_type, port_number, pad, queue_id):
    print ('%s StatReq Type: Queue(%s): Port_Number: %s Pad: %s Queue_id: %s' %
           (of_xid, stat_type, green(port_number), pad, queue_id))


def print_ofp_statReqVendor(of_xid, stat_type, vendor_id):
    print ('%s StatReq Type: Vendor(%s): Vendor_ID: %s' % (of_xid, stat_type,
           vendor_id))


def print_ofp_statResDesc(of_xid, stat_type, mfr_desc, hw_desc, sw_desc,
                          serial_num, dp_desc):
    print ('%s StatRes Type: Description(%s)' % (of_xid, stat_type))
    print ('%s StatRes mfr_desc: %s' % (of_xid, mfr_desc))
    print ('%s StatRes hw_desc: %s' % (of_xid, hw_desc))
    print ('%s StatRes sw_desc: %s' % (of_xid, sw_desc))
    print ('%s StatRes serial_num: %s' % (of_xid, serial_num))
    print ('%s StatRes dp_desc: %s' % (of_xid, dp_desc))


def print_ofp_statResFlow(of_xid, stat_type, match, res_flow):
    print ('%s StatRes Type: Flow(%s)' % (of_xid, stat_type))
    print ('%s StatRes Length: %s Table_id: %s Pad: %s ' %
           (of_xid, res_flow['length'], res_flow['table_id'], res_flow['pad']))
    print ('%s StatRes' % of_xid),
    print_ofp_match('', match)
    print ('%s StatRes duration_sec: %s, duration_nsec: %s, priority: %s,'
           ' idle_timeout: %s, hard_timeout: %s, pad: %s, cookie: %s,'
           ' packet_count: %s, byte_count: %s' %
           (of_xid, res_flow['duration_sec'], res_flow['duration_nsec'],
            res_flow['priority'], res_flow['idle_timeout'],
            res_flow['hard_timeout'], res_flow['pad'],
            res_flow['cookie'],
            res_flow['packet_count'], res_flow['byte_count']))


def print_ofp_statResAggregate(of_xid, stat_type, res_flow):
    print ('%s StatRes Type: Aggregate(%s)' % (of_xid, stat_type))
    print ('%s StatRes packet_count: %s, byte_count: %s flow_count: %s '
           'pad: %s' %
           (of_xid, res_flow['packet_count'], res_flow['byte_count'],
            res_flow['flow_count'], res_flow['pad']))


def print_ofp_statResTable(of_xid, stat_type, res_flow):
    print ('%s StatRes Type: Table(%s)' % (of_xid, stat_type))
    print ('%s StatRes table_id: %s, pad: %s, name: "%s", wildcards: %s, '
           'max_entries: %s, active_count: %s, lookup_count: %s, '
           'matched_count: %s' %
           (of_xid, res_flow['table_id'], res_flow['pad'],
            res_flow['name'], hex(res_flow['wildcards']),
            res_flow['max_entries'], res_flow['active_count'],
            res_flow['lookup_count'], res_flow['matched_count']))


def print_ofp_statResPort(of_xid, stat_type, res_flow):
    print ('%s StatRes Type: Port(%s)' % (of_xid, stat_type))
    print ('%s StatRes port_no: %s rx_packets: %s rx_bytes: %s rx_errors: %s'
           ' rx_crc_err: %s rx_dropped: %s rx_over_err: %s rx_frame_err: %s\n'
           '%s StatRes port_no: %s tx_packets: %s tx_bytes: %s tx_errors: %s'
           ' tx_dropped: %s collisions: %s pad: %s' %
           (of_xid, red(res_flow['port_number']), res_flow['rx_packets'],
            res_flow['rx_bytes'], res_flow['rx_errors'], res_flow['rx_crc_err'],
            res_flow['rx_dropped'], res_flow['rx_over_err'],
            res_flow['rx_frame_err'], of_xid, red(res_flow['port_number']),
            res_flow['tx_packets'], res_flow['tx_bytes'], res_flow['tx_errors'],
            res_flow['tx_dropped'], res_flow['collisions'], res_flow['pad']))


def print_ofp_statResQueue(of_xid, stat_type, res_flow):
    print ('%s StatRes Type: Queue(%s)' % (of_xid, stat_type))
    print ('%s StatRes queue_id: %s length: %s pad: %s'
           ' tx_bytes: %s tx_packets: %s tx_errors: %s' %
           (of_xid, res_flow['queue_id'], res_flow['length'], res_flow['pad'],
            res_flow['tx_bytes'], res_flow['tx_packets'],
            res_flow['tx_errors']))


def print_ofp_statResVendor(of_xid, stat_type, res_flow):
    print ('%s StatRes Type: Vendor(%s)' % (of_xid, stat_type))
    print ('%s StatRes vendor_id: %s' % (of_xid, res_flow['vendor_id']))


def print_ofp_statResVendorData(of_xid, data):
    print '%s StatRes Vendor Data: %s' % (of_xid, data)


def print_ofp_getConfigRes(of_xid, flag, miss):
    print ('%s OpenFlow GetConfigRes - Flag: %s Miss_send_len: %s' %
           (of_xid, flag, miss))


def print_ofp_setConfig(of_xid, flag, miss):
    print ('%s OpenFlow SetConfig - Flag: %s Miss_send_len: %s' %
           (of_xid, flag, miss))


def print_echoreq(pkt):
    print 'OpenFlow Echo Request'


def print_echores(pkt):
    print 'OpenFlow Echo Reply'


def print_portStatus(of_xid, reason, pad):
    print ('%s OpenFlow PortStatus - Reason: %s Pad: %s' %
           (of_xid, reason, pad))


def print_packetInOut_layer2(of_xid, eth):
    print ('%s' % of_xid),
    gen.prints.print_layer2(eth)


def print_packetInOut_vlan(of_xid, vlan):
    print ('%s Ethernet:' % of_xid),
    gen.prints.print_vlan(vlan)


def print_packetIn(pkt):
    packetIn = pkt.of_body['print_packetIn']

    # If we have filters (-F)
    # filters = pkt.sanitizer['packetIn_filter']

    # if len(filters) > 0:
    #    if filters['switch_dpid'] == "any":
    #    should_print = True _print_packetIn(of_xid, packetIn, eth, vlan, lldp)
    #    elif filters['switch_dpid'] == lldp['c_id']:
    #        if (filters['in_port'] == "any" or
    #           filters['in_port'] == lldp['in_port']):
    #            _print_packetIn(of_xid, packetIn, eth, vlan, lldp)
    # else:
    #    _print_packetIn(of_xid, packetIn, eth, vlan, lldp)

    print ('PacketIn: buffer_id: %s total_len: %s in_port: %s reason: %s '
           'pad: %s' %
           (hex(packetIn['buffer_id']), packetIn['total_len'],
            green(packetIn['in_port']), green(packetIn['reason']),
            packetIn['pad']))


# a print_lldp function was created on gen.prints
# remove this
def print_packetInOut_lldp(of_xid, lldp):
    print ('%s LLDP: Chassis Type(%s) Length: %s SubType: %s ID: %s\n'
           '%s LLDP: Port Type(%s) Length: %s SubType: %s ID: %s\n'
           '%s LLDP: TTL(%s) Length: %s Seconds: %s\n'
           '%s LLDP: END(%s) Length: %s' %
           (of_xid, lldp['c_type'], lldp['c_length'], lldp['c_subtype'],
            green(lldp['c_id']), of_xid, lldp['p_type'], lldp['p_length'],
            lldp['p_subtype'], green(lldp['p_id']), of_xid, lldp['t_type'],
            lldp['t_length'], lldp['t_ttl'], of_xid, lldp['e_type'],
            lldp['e_length']))


def print_packetOut(pkt):
    packetOut = pkt.of_body['print_packetOut']
    print ('PacketOut: buffer_id: %s in_port: %s actions_len: %s' %
           (hex(packetOut['buffer_id']),
            green(of10.dissector.get_phy_port_id(packetOut['in_port'])),
            packetOut['actions_len']))


def print_queueReq(of_xid, queueConfReq):
    print ('%s QueueGetConfigReq Port: %s Pad: %s' %
           (of_xid, queueConfReq['port'], queueConfReq['pad']))


def print_queueRes(of_xid, queueConfRes):
    print ('%s QueueGetConfigRes Port: %s Pad: %s' %
           (of_xid, queueConfRes['port'], queueConfRes['pad']))


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
