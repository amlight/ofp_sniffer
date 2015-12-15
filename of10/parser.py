'''
   Parser for OpenFlow 1.0
'''

from struct import unpack
import of10.dissector
import of10.prints
import socket
import struct
import gen.tcpip
import of10.vendors
import gen.proxies


def process_ofp_type(pkt):
    if pkt.of_h['type'] == 0:
        result = parse_Hello(pkt)
    elif pkt.of_h['type'] == 1:
        result = parse_Error(pkt)
    elif pkt.of_h['type'] == 2:
        result = parse_EchoReq(pkt)
    elif pkt.of_h['type'] == 3:
        result = parse_EchoRes(pkt)
    elif pkt.of_h['type'] == 4:
        result = parse_Vendor(pkt)
    elif pkt.of_h['type'] == 5:
        result = parse_FeatureReq(pkt)
    elif pkt.of_h['type'] == 6:
        result = parse_FeatureRes(pkt)
    elif pkt.of_h['type'] == 7:
        result = parse_GetConfigReq(pkt)
    elif pkt.of_h['type'] == 8:
        result = parse_GetConfigRes(pkt)
    elif pkt.of_h['type'] == 9:
        result = parse_SetConfig(pkt)
    elif pkt.of_h['type'] == 10:
        result = parse_PacketIn(pkt)
    elif pkt.of_h['type'] == 11:
        result = parse_FlowRemoved(pkt)
    elif pkt.of_h['type'] == 12:
        result = parse_PortStatus(pkt)
    elif pkt.of_h['type'] == 13:
        result = parse_PacketOut(pkt)
    elif pkt.of_h['type'] == 14:
        result = parse_FlowMod(pkt)
    elif pkt.of_h['type'] == 15:
        result = parse_PortMod(pkt)
    elif pkt.of_h['type'] == 16:
        result = parse_StatsReq(pkt)
    elif pkt.of_h['type'] == 17:
        result = parse_StatsRes(pkt)
    elif pkt.of_h['type'] == 18:
        result = parse_BarrierReq(pkt)
    elif pkt.of_h['type'] == 19:
        result = parse_BarrierRes(pkt)
    elif pkt.of_h['type'] == 20:
        result = parse_QueueGetConfigReq(pkt)
    elif pkt.of_h['type'] == 21:
        result = parse_QueueGetConfigRes(pkt)
    else:
        return 0
    return result


# *************** Hello *****************
def parse_Hello(pkt):
    pkt.prepare_printing('print_of_hello', None)
    return 1


# ************** Error *****************
def parse_Error(pkt):
    of_error = pkt.this_packet[0:4]
    ofe = unpack('!HH', of_error)

    error = {'type': ofe[0], 'code': ofe[1]}
    pkt.prepare_printing('print_of_error', error)
    return 1


# ************ EchoReq *****************
def parse_EchoReq(pkt):
    pkt.prepare_printing('print_echoreq', None)
    return 1


# ************ EchoRes *****************
def parse_EchoRes(pkt):
    pkt.prepare_printing('print_echores', None)
    return 1


# ************ Vendor ******************
def parse_Vendor(pkt):
    of_vendor = pkt.this_packet[0:4]
    ofv = unpack('!L', of_vendor)
    pkt.prepare_printing('print_of_vendor', ofv[0])

    # Future - version 0.4
    # If code 8992 = NICIRA
    #if ofv[0] == 8992:
    #    of10.vendors.parse_nicira(packet, h_size+4, of_xid)

    return 1


# *********** FeatureReq ***************
def parse_FeatureReq(pkt):
    pkt.prepare_printing('print_of_feature_req', None)
    return 1


# *********** FeatureRes ***************
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


def _parse_phy_ports(packet):
    phy = unpack('!H6s16sLLLLLL', packet)

    port_id = of10.dissector.get_phy_port_id(phy[0])
    hw_addr = of10.prints.eth_addr(phy[1])
    config = _parse_phy_config(phy[3])
    state = _parse_phy_state(phy[4])
    curr = _parse_phy_curr(phy[5])
    advertised = _parse_phy_curr(phy[6])
    supported = _parse_phy_curr(phy[7])
    peer = _parse_phy_curr(phy[8])

    phy_ports = {'port_id': port_id,
                 'hw_addr': hw_addr,
                 'name': phy[2],
                 'config': config,
                 'state': state,
                 'curr': curr,
                 'advertised': advertised,
                 'supported': supported,
                 'peer': peer}
    return phy_ports


def parse_FeatureRes(pkt):
    of_fres = pkt.this_packet[0:24]
    ofrs = unpack('!8sLB3sLL', of_fres)
    f_res = {'datapath_id': ofrs[0], 'n_buffers': ofrs[1], 'n_tbls': ofrs[2],
             'pad': ofrs[3]}
    pkt.prepare_printing('print_of_feature_res', f_res)

    # 'capabilities': ofrs[4], 'actions': ofrs[5]}
    caps = []
    caps = _parse_capabilities(ofrs[4])
    pkt.prepare_printing('print_of_feature_res_caps', caps)

    actions = []
    actions = _parse_actions(ofrs[5])
    pkt.prepare_printing('print_of_feature_res_actions', actions)

    # Ports description?
    start = 24
    while len(pkt.this_packet[start:]) > 0:
        ports = _parse_phy_ports(pkt.this_packet[start:start+48])
        pkt.prepare_printing('print_of_feature_res_ports', ports)
        start = start + 48

    return 1


# ***************** GetConfigReq *********************
def parse_GetConfigReq(pkt):
    pkt.prepare_printing('print_of_getconfig_req', pkt)
    return 1


# ***************** GetConfigRes ********************
def _parse_SetGetConfig(packet, h_size):
    pkt_raw = packet[h_size:h_size+4]
    pkt_list = unpack('!HH', pkt_raw)
    flag = of10.dissector.get_configres_flags(pkt_list[0])
    miss_send_len = pkt_list[1]
    return {'flag': flag, 'miss_send_len': miss_send_len}


def parse_GetConfigRes(pkt):
    getConfig = _parse_SetGetConfig(pkt.this_packet, 0)
    pkt.prepare_printing('print_ofp_getConfigRes', getConfig)
    return 1


# ******************* SetConfig **********************
def parse_SetConfig(pkt):
    setConfig = _parse_SetGetConfig(pkt.this_packet, 0)
    pkt.prepare_printing('print_ofp_setConfig', setConfig)
    return 1


# ****************** PacketIn ************************
def _parse_ethernet_lldp_PacketInOut(packet, start):
    # Ethernet
    eth = gen.tcpip.get_ethernet_frame(packet[start:start+14], 1)
    start = start + 14
    etype = '0x0000'
    vlan = {}
    # VLAN or not
    if eth['protocol'] in [33024]:
        vlan = gen.tcpip.get_ethernet_vlan(packet[start:start+2])
        start = start + 2
        # If VLAN exists, there is a next eth['protocol']
        etype = gen.tcpip.get_next_etype(packet[start:start+2])
        start = start + 2
    else:
        etype = eth['protocol']
    # LLDP
    lldp = {}
    if etype in [35020, 35138]:
        lldp = gen.tcpip.get_lldp(packet[start:])
        return eth, vlan, lldp, start
    eth['protocol'] = etype
    return eth, vlan, {}, start


def _parse_other_types(packet, start, eth, pkt):
    # OESS FVD
    if eth['protocol'] in [34998]:
        message = {'message': 'OESS FVD'}
        pkt.prepare_printing('print_string', message)
    elif eth['protocol'] in [35020]:
        # If it gets here, means that the LLDP packet is MalFormed
        message = {'message': 'LLDP Packet MalFormed'}
        pkt.prepare_printing('print_string', message)
    elif eth['protocol'] in [2048]:
        ip = gen.tcpip.get_ip_packet(packet, start)
        if ip['protocol'] is 6:
            tcp = gen.tcpip.get_tcp_stream(packet, start + ip['length'])
            pkt.prepare_printing('print_layer3', ip)
            pkt.prepare_printing('print_tcp', tcp)
    elif eth['protocol'] in [2054]:
        arp = gen.tcpip.get_arp(packet[start:])
       # pkt.prepare_printing('print_arp', arp)
    else:
        string = 'Ethertype %s not dissected' % hex(eth['protocol'])
        message = {'message': string}
        pkt.prepare_printing('print_string', message)


def _print_packetIn(of_xid, packetIn, eth, vlan, lldp):
    of10.prints.print_ofp_packetIn(of_xid, packetIn)
    of10.prints.print_packetInOut_layer2(of_xid, eth)
    if len(vlan) != 0:
        of10.prints.print_packetInOut_vlan(of_xid, vlan)
    if len(lldp) != 0:
        of10.prints.print_packetInOut_lldp(of_xid, lldp)


def parse_PacketIn(pkt):
    # buffer_id(32), total_len(16), in_port(16), reason(8), pad(8)
    pkt_raw = pkt.this_packet[0:10]
    p_in = unpack('!LHHBB', pkt_raw)
    reason = of10.dissector.get_packetIn_reason(p_in[3])
    packetIn = {'buffer_id': p_in[0], 'total_len': p_in[1], 'in_port': p_in[2],
                'reason': reason, 'pad': p_in[4]}

    pkt.prepare_printing('print_packetIn', packetIn)

    eth, vlan, lldp, offset = _parse_ethernet_lldp_PacketInOut(pkt.this_packet,
                                                               10)

    pkt.prepare_printing('print_layer2_pktIn', eth)
    if len(vlan) > 0:
        pkt.prepare_printing('print_vlan', vlan)

    if len(lldp) == 0:
        _parse_other_types(pkt.this_packet[offset:], 0, eth, pkt)
    else:
        pkt.prepare_printing('print_lldp', lldp)

    # If we have filters (-F)
    # filters = sanitizer['packetIn_filter']

    # if len(filters) > 0:
    #     if filters['switch_dpid'] == "any":
    #         _print_packetIn(of_xid, packetIn, eth, vlan, lldp)
    #     elif filters['switch_dpid'] == lldp['c_id']:
    #         if (filters['in_port'] == "any" or
    #            filters['in_port'] == lldp['in_port']):
    #             _print_packetIn(of_xid, packetIn, eth, vlan, lldp)
    # else:
    #     _print_packetIn(of_xid, packetIn, eth, vlan, lldp)

    return 1


# ******************** FlowRemoved ***************************
def parse_FlowRemoved(pkt):
    ofmatch = _parse_OFMatch(pkt.this_packet, 0)
    pkt.prepare_printing('print_ofp_match', ofmatch)

    of_rem_body = pkt.this_packet[40:40+40]
    ofrem = unpack('!QHBBLLHBBQQ', of_rem_body)
    cookie = ofrem[0] if ofrem[0] > 0 else 0
    cookie = '0x' + format(cookie, '02x')
    reason = of10.dissector.get_flow_removed_reason(ofrem[2])

    ofrem = {'cookie': cookie, 'priority': ofrem[1], 'reason': reason,
             'pad': ofrem[3], 'duration_sec': ofrem[4],
             'duration_nsec': ofrem[5], 'idle_timeout': ofrem[6],
             'pad2': ofrem[7], 'pad3': ofrem[8],
             'packet_count': ofrem[9], 'byte_count': ofrem[10]}

    pkt.prepare_printing('print_ofp_flow_removed', ofrem)
    return 1


# ******************* PortStatus *****************************
def parse_PortStatus(pkt):
    port_raw = pkt.this_packet[0:8]
    port = unpack('!B7s', port_raw)
    reason = of10.dissector.get_portStatus_reason(port[0])
    p_status = {'reason': reason, 'pad': port[1]}
    pkt.prepare_printing('print_portStatus', p_status)

    ports = _parse_phy_ports(pkt.this_packet[8:64])
    pkt.prepare_printing('print_of_feature_res_ports', ports)
    return 1


# ******************* PacketOut *****************************
def parse_PacketOut(pkt):
    # buffer_id(32), in_port(16), actions_len(16)
    pkt_raw = pkt.this_packet[0:8]
    p_out = unpack('!LHH', pkt_raw)
    packetOut = {'buffer_id': p_out[0], 'in_port': p_out[1],
                 'actions_len': p_out[2]}

    pkt.prepare_printing('print_packetOut', packetOut)
    # Actions
    start = 8
    actions_dict = _parse_OFAction(pkt.this_packet[start:start+packetOut['actions_len']], 0)
    pkt.prepare_printing('print_actions', actions_dict)

    start = start + packetOut['actions_len']

    # Check if we still have content in the PacketOut
    if len(pkt.this_packet[start:]) == 0:
        return 1

    # Ethernet
    eth = gen.tcpip.get_ethernet_frame(pkt.this_packet[start:start+14], 1)
    pkt.prepare_printing('print_layer2_pktIn', eth)
    start = start + 14
    etype = '0x0000'
    # VLAN or not
    if eth['protocol'] in [33024]:
        vlan = gen.tcpip.get_ethernet_vlan(pkt.this_packet[start:start+2])
        if len(vlan) > 0:
            pkt.prepare_printing('print_vlan', vlan)
        start = start + 2
        # If VLAN exists, there is a next eth['protocol']
        etype = gen.tcpip.get_next_etype(pkt.this_packet[start:start+2])
        start = start + 2
    else:
        etype = eth['protocol']
    if etype in [35020, 35138]:
        # LLDP TLV
        lldp = gen.tcpip.get_lldp(pkt.this_packet[start:])
        if len(lldp) is 0:
            print 'LLDP Packet MalFormed'
        else:
            # Support for FSFW/Proxy
            gen.proxies.support_fsfw(pkt.print_options, lldp)
            pkt.prepare_printing('print_lldp', lldp)

    return 1


# ********************* FlowMod ***************************
def process_dst_subnet(wcard):
    OFPFW_NW_DST_SHIFT = 14
    OFPFW_NW_DST_MASK = 1032192
    nw_dst_bits = (wcard & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT
    return ((32 - nw_dst_bits) if nw_dst_bits < 32 else 0)


def process_src_subnet(wcard):
    OFPFW_NW_SRC_SHIFT = 8
    OFPFW_NW_SRC_MASK = 16128
    nw_src_bits = (wcard & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT
    return ((32 - nw_src_bits) if nw_src_bits < 32 else 0)


def _process_wildcard(wcard):
    wildcard = {1: 'in_port',
                2: 'dl_vlan',
                4: 'dl_src',
                8: 'dl_dst',
                16: 'dl_type',
                32: 'nw_prot',
                64: 'tp_src',
                128: 'tp_dst',
                1048576: 'dl_vlan_pcp',
                2097152: 'nw_tos'}

    return wildcard.get(wcard)


def get_ip_from_long(long_ip):
    return (socket.inet_ntoa(struct.pack('!L', long_ip)))


def _parse_OFMatch(packet, h_size):
    of_match = packet[h_size:h_size+40]
    ofm = unpack('!LH6s6sHBBHBBHLLHH', of_match)
    wildcard = ofm[0]
    dl_src = of10.prints.eth_addr(ofm[2])
    dl_dst = of10.prints.eth_addr(ofm[3])
    nw_src = get_ip_from_long(ofm[11])
    nw_dst = get_ip_from_long(ofm[12])
    etype = hex(ofm[7])

    ofmatch = {'wildcards': ofm[0], 'in_port': ofm[1], 'dl_src': dl_src,
               'dl_dst': dl_dst, 'dl_vlan': ofm[4], 'dl_vlan_pcp': ofm[5],
               'dl_type': etype, 'nw_tos': ofm[8], 'nw_prot': ofm[9],
               'nw_src': nw_src, 'nw_dst': nw_dst, 'tp_src': ofm[13],
               'tp_dst': ofm[14]}

    if wildcard >= ((1 << 22) - 1):
        ofmatch = {'wildcards': 4194303}
        return ofmatch
    elif wildcard == 0:
        ofmatch = {'wildcards': 0}
        return ofmatch
    else:
        src_netmask = process_src_subnet(wildcard)
        if src_netmask == 0:
            ofmatch.pop('nw_src')
        else:
            ofmatch['nw_src'] = str(ofmatch['nw_src']) + '/' + str(src_netmask)
        dst_netmask = process_dst_subnet(wildcard)
        if dst_netmask == 0:
            ofmatch.pop('nw_dst')
        else:
            ofmatch['nw_dst'] = str(ofmatch['nw_dst']) + '/' + str(dst_netmask)
        for i in range(0, 8):
            mask = 2**i
            aux = wildcard & mask
            if aux != 0:
                ofmatch.pop(_process_wildcard(mask))

        for i in range(20, 22):
            mask = 2**i
            aux = wildcard & mask
            if aux != 0:
                ofmatch.pop(_process_wildcard(mask))

    return ofmatch


def _parse_OFBody(packet, h_size):
    of_mod_body = packet[h_size+40:h_size+40+24]
    ofmod = unpack('!QHHHHLHH', of_mod_body)
    ofmod_cookie = ofmod[0] if ofmod[0] > 0 else 0
    ofmod_cookie = '0x' + format(ofmod_cookie, '02x')
    ofmod_buffer_id = '0x' + format(ofmod[5], '02x')

    ofbody = {'cookie': ofmod_cookie, 'command': ofmod[1],
              'idle_timeout': ofmod[2], 'hard_timeout': ofmod[3],
              'priority': ofmod[4], 'buffer_id': ofmod[5],
              'buffer_id': ofmod_buffer_id, 'out_port': ofmod[6],
              'flags': ofmod[7]}
    return ofbody


def get_action(action_type, length, payload):
    # 0 - OUTPUT. Returns port and max_length
    if action_type == 0:
        type_0 = unpack('!HH', payload)
        return type_0[0], type_0[1]
    # 1 - SetVLANID. Returns VID and pad
    elif action_type == 1:
        type_1 = unpack('!HH', payload)
        return type_1[0], type_1[1]
    # 2 - SetVLANPCP
    elif action_type == 2:
        type_2 = unpack('!B3s', payload)
        return type_2[0], type_2[1]
    # 3 - StripVLAN
    elif action_type == 3:
        pass
    # 4 - SetDLSrc
    elif action_type == 4:
        type_4 = unpack('!6s6s', payload)
        return type_4[0], type_4[1]
    # 5 - SetDLDst
    elif action_type == 5:
        type_5 = unpack('!6s6s', payload)
        return type_5[0], type_5[1]
    # 6 - SetNWSrc
    elif action_type == 6:
        type_6 = unpack('!L', payload)
        return get_ip_from_long(type_6[0])
    # 7 - SetNWDst
    elif action_type == 7:
        type_7 = unpack('!L', payload)
        return get_ip_from_long(type_7[0])
    # 8 - SetNWTos
    elif action_type == 8:
        type_8 = unpack('!B3s', payload)
        return type_8[0], type_8[1]
    # 9 - SetTPSrc
    elif action_type == 9:
        type_9 = unpack('!HH', payload)
        return type_9[0], type_9[1]
    # a - SetTPDst
    elif action_type == int('a', 16):
        type_a = unpack('!HH', payload)
        return type_a[0], type_a[1]
    # b - Enqueue
    elif action_type == int('b', 16):
        type_b = unpack('!H6sL', payload)
        return type_b[0], type_b[1], type_b[2]
    # ffff - Vendor
    elif action_type == int('ffff', 16):
        type_f = unpack('!L', payload)
        return type_f[0]


def _parse_OFAction(packet, start):
    '''
        Actions
    '''
    # Actions: Header = 4 , plus each possible action
    # Payload varies:
    #  4 for types 0,1,2,6,7,8,9,a,ffff
    #  0 for type 3
    #  12 for types 4,5,b
    action_header = 4
    # Add all actions to a list for future printing
    actions_list = []
    while (1):
        ofp_action = packet[start:start + action_header]
        if len(ofp_action) > 0:
            # Get type and length
            ofa = unpack('!HH', ofp_action)
            ofa_type = ofa[0]
            ofa_length = ofa[1]

            start = start + action_header
            if ofa_type == 4 or ofa_type == 5 or ofa_type == int('b', 16):
                total_length = 12
                ofa_action_payload = packet[start:start + 12]
            else:
                total_length = 4
                ofa_action_payload = packet[start:start + 4]

            actions_dict = {'type': ofa_type, 'length': ofa_length,
                            'payload': ofa_action_payload}
            actions_list.append(actions_dict)
            # Next packet would start at..
            start = start + total_length
        else:
            break

    return actions_list


def parse_FlowMod(pkt):
    ofmatch = _parse_OFMatch(pkt.this_packet, 0)
    pkt.prepare_printing("print_ofp_match", ofmatch)

    ofbody = _parse_OFBody(pkt.this_packet, 0)
    pkt.prepare_printing("print_ofp_body", ofbody)

    ofactions = []

    # Actions: Header = 4 , plus each possible action
    actions_start = 64
    actions_dict = _parse_OFAction(pkt.this_packet, actions_start)
    pkt.prepare_printing('print_actions', actions_dict)

    return 1


# ********************* PortMod ****************************
def parse_PortMod(pkt):
    # port(16), hw_addr(48), config(32), mask(32), advertise(32), pad(32)
    pmod_raw = pkt.this_packet[0:24]
    pmod = unpack('!H6sLLLL', pmod_raw)

    config = _parse_phy_config(pmod[2])
    mask = _parse_phy_config(pmod[3])
    advertise = _parse_phy_curr(pmod[4])
    portMod = {'port': pmod[0], 'hw_addr': pmod[1], 'config': config,
               'mask': mask, 'advertise': advertise, 'pad': pmod[5]}

    pkt.prepare_printing('print_PortMod', portMod)
    return 1


# ******************** StatReq ****************************
def parse_StatsReq(pkt):
    '''
        Process the StatsReq
    '''
    # Get type = 16bits
    # Get flags = 16bits
    of_stat_req = pkt.this_packet[0:4]
    ofstat = unpack('!HH', of_stat_req)
    stat_type = ofstat[0]
    # FLags were not defined yet. Ignoring.
    # flags = ofstat[1]
    start = 4

    # 7 Types available
    if stat_type == 0:
        # Description
        # No extra fields
        pkt.prepare_printing('print_ofp_statReqDesc', stat_type)

    elif stat_type == 1 or stat_type == 2:
        # Flow(1) or Aggregate(2)
        # Fields: match(40), table_id(8), pad(8), out_port(16)
        of_match = _parse_OFMatch(pkt.this_packet, start)
        # 44 Bytes (40B from Match, 4 from header)
        of_stat_req = pkt.this_packet[start+40:start+40+4]
        ofstat = unpack('!BBH', of_stat_req)
        table_id = ofstat[0]
        pad = ofstat[1]
        out_port = ofstat[2]
        stats = {'type': stat_type, 'match': of_match, 'table_id': table_id, 'pad': pad,
                 'out_port': out_port}
        pkt.prepare_printing('print_ofp_statReqFlowAggregate', stats)

    elif stat_type == 3:
        # Table
        # No extra fields
        pkt.prepare_printing('print_ofp_statReqTable', stat_type)

    elif stat_type == 4:
        # Port
        # Fields: port_number(16), pad(48)
        of_stat_req = pkt.this_packet[start:start+8]
        ofstat = unpack('!H6s', of_stat_req)
        port_number = ofstat[0]
        pad = ofstat[1]
        stats = {'type': stat_type, 'port_number': port_number, 'pad': pad}
        pkt.prepare_printing('print_ofp_statReqPort', stats)

    elif stat_type == 5:
        # Queue
        # Fields: port_number(16), pad(16), queue_id(32)
        of_stat_req = pkt.this_packet[start:start+8]
        ofstat = unpack('!HHL', of_stat_req)
        port_number = ofstat[0]
        pad = ofstat[1]
        queue_id = ofstat[2]
        stats = {'type': stat_type, 'port_number': port_number, 'pad': pad,
                 'queue_id': queue_id}
        pkt.prepare_printing('print_ofp_statReqQueue', stats)

    elif stat_type == 65535:
        # Vendor
        # Fields: vendor_id(32) + data
        of_stat_req = pkt.this_packet[start:start+4]
        ofstat = unpack('!L', of_stat_req)
        vendor_id = ofstat[0]
        stats = {'type': stat_type, 'vendor_id': vendor_id}
        pkt.prepare_printing('print_ofp_statReqVendor', stats)

    else:
        print 'StatReq: Unknown Type: %s' % stat_type

    return 1


# *********************** StatsRes ****************************
def parse_StatsRes(pkt):
    # Get type = 16bits
    # Get flags = 16bits
    of_stat_req = pkt.this_packet[0:4]
    ofstat = unpack('!HH', of_stat_req)
    stat_type = ofstat[0]
    # flags = ofstat[1]
    start = 4

    # 7 Types available
    if stat_type == 0:
        # Description
        # Fields: mfr_desc(2048), hw_desc(2048), sw_desc(2048), serial_num(256),
        #  dp_desc(2048)
        desc_raw = pkt.this_packet[start:start+1056]
        desc = unpack('!256s256s256s32s256s', desc_raw)
        stats = {'mfr_desc': desc[0],
                 'hw_desc': desc[1],
                 'sw_desc': desc[2],
                 'serial_num': desc[3],
                 'dp_desc': desc[4],
                 'type': stat_type}
        pkt.prepare_printing('print_ofp_statResDesc', stats)

    elif stat_type == 1:
        # Flow(1)
        # Fields: length(16), table_id(8), pad(8), match(40), duration_sec(32),
        #  duration_nsec(32), priority(16), idle_timeout(16), hard_timeout(16),
        #  pad(48), cookie(64), packet_count(64), byte_count(64), actions[]
        count = len(pkt.this_packet[0:]) - 4
        flows = []
        while (count > 0):
            flow_raw = pkt.this_packet[start:start+4]
            flow = unpack('!HBB', flow_raw)
            res_flow = {'length': flow[0], 'table_id': flow[1], 'pad': flow[2]}
            of_match = _parse_OFMatch(pkt.this_packet, start+4)

            flow_raw = pkt.this_packet[start+44:start+44+44]
            flow = unpack('!LLHHH6sQQQ', flow_raw)
            res_flow.update({'duration_sec': flow[0], 'duration_nsec': flow[1],
                             'priority': flow[2], 'idle_timeout': flow[3],
                             'hard_timeout': flow[4], 'pad2': flow[5],
                             'cookie': flow[6], 'packet_count': flow[7],
                             'byte_count': flow[8]})
            stats = {'type': stat_type, 'match': of_match, 'res_flow': res_flow}

            # Process Actions[]
            end = res_flow['length'] - (4 + 40 + 44)
            actions = pkt.this_packet[start+88:start+88+end]
            actions_dict = _parse_OFAction(actions, 0)

            stats = {'type': stat_type, 'match': of_match,
                     'res_flow': res_flow, 'print_actions': actions_dict}

            flows.append(stats)

            count = count - int(res_flow['length'])
            start = start + int(res_flow['length'])

        # important to have a sequencial list here because there are multiple
        # flows. So, print_ofp_statResFlow will print a list of flows.
        pkt.prepare_printing('print_ofp_statResFlowArray', flows)

    elif stat_type == 2:
        # Aggregate(2)
        # Fields: packet_count(64), byte_count(64), flow_count(32), pad(32)
        flow_raw = pkt.this_packet[start:start+24]
        flow = unpack('!QQLL', flow_raw)
        res_flow = {'type': stat_type, 'packet_count': flow[0],
                    'byte_count': flow[1], 'flow_count': flow[2],
                    'pad': flow[3]}
        pkt.prepare_printing('print_ofp_statResAggregate', res_flow)

    elif stat_type == 3:
        # Table
        # Fields: table_id(8), pad(24), name(256), wildcards(32),
        #  max_entries(32), active_count(32), lookup_count(64),
        #  matched_count(64)
        flow_raw = pkt.this_packet[start:start+64]
        flow = unpack('!B3s32sLLLQQ', flow_raw)
        res_flow = {'type': stat_type, 'table_id': flow[0], 'pad': flow[1],
                    'name': flow[2], 'wildcards': flow[3],
                    'max_entries': flow[4], 'active_count': flow[5],
                    'lookup_count': flow[6], 'matched_count': flow[7]}
        pkt.prepare_printing('print_ofp_statResTable', res_flow)

    elif stat_type == 4:
        # Port
        # Fields: port_number(16), pad(48), rx_packets(64), tx_packets(64),
        #  rx_bytes(64), tx_bytes(64), rx_dropped(64), tx_dropped(64),
        #  rx_errors(64), tx_errors(64), rx_frame_err(64), rx_over_err(64),
        #  rx_crc_err(64), collisions(64)
        count = len(pkt.this_packet[0:]) - 4
        ports = []
        while (count > 0):
            flow_raw = pkt.this_packet[start:start+104]
            flow = unpack('!H6sQQQQQQQQQQQQ', flow_raw)
            port = {'type': stat_type, 'port_no': flow[0], 'pad': flow[1],
                     'rx_packets': flow[2], 'tx_packets': flow[3],
                     'rx_bytes': flow[4], 'tx_bytes': flow[5],
                     'rx_dropped': flow[6], 'tx_dropped': flow[7],
                     'rx_errors': flow[8], 'tx_errors': flow[9],
                     'rx_frame_err': flow[10], 'rx_over_err': flow[11],
                     'rx_crc_err': flow[12], 'collisions': flow[13]}

            ports.append(port)

            count = count - 104
            start = start + 104

        pkt.prepare_printing('print_ofp_statResPortArray', ports)

    elif stat_type == 5:
        # Queue
        # Fields: length(16), pad(16), queue_id(32), tx_bytes(64),
        #  tx_packets(64), tx_errors(64)
        count = len(pkt.this_packet[0:]) - 4
        queues = []
        while (count > 0):
            flow_raw = pkt.this_packet[start:start+32]
            flow = unpack('!HHLQQQ', flow_raw)
            queue = {'length': flow[0], 'pad': flow[1], 'queue_id': flow[2],
                     'tx_bytes': flow[3], 'tx_packets': flow[4],
                     'tx_errors': flow[5], 'type': stat_type}
            queues.append(queue)
            count = count - 32
            start = start + 32

        pkt.prepare_printing('print_ofp_statResQueueArray', queues)

    elif stat_type == 65535:
        # Vendor
        # Fields: vendor_id(32), data(?)
        flow_raw = pkt.this_packet[start:start+4]
        flow = unpack('!L', flow_raw)
        vendor_flow = {'type': stat_type, 'vendor_id': flow[0]}
        pkt.prepare_printing('print_ofp_statResVendor', vendor_flow)


        pkt.prepare_printing('print_ofp_statResVendorData',
                             pkt.this_packet[start+4:])
        #start = start + 4
        #data = []
        #count = len(packet[0:])

        #import hexdump
        #hexdump.hexdump(pkt.this_packet[start:])
        #print
        # while (start < count):
        #    flow_raw = pkt.this_packet[start:start+1]
        #    flow = unpack('!B', flow_raw)
        #    data.append(str(flow[0]))
        #    start = start + 1
        # pkt.prepare_printing('print_ofp_statResVendorData', ''.join(data))

    else:
        print ('StatRes: Unknown Type: %s' % (stat_type))
    return 1


# ********************** BarrierReq ***********************
def parse_BarrierReq(pkt):
    pkt.prepare_printing('print_of_BarrierReq', None)
    return 1


# ********************** BarrierRes ***********************
def parse_BarrierRes(pkt):
    pkt.prepare_printing('print_of_BarrierReply', None)
    return 1


# ******************* QueueGetConfigReq *******************
def parse_QueueGetConfigReq(pkt):
    queue_raw = pkt.this_packet[0:4]
    queue = unpack('!HH', queue_raw)
    queueConfReq = {'port': queue[0], 'pad': queue[1]}
    pkt.prepare_printing('print_queueReq', queueConfReq)
    return 1


# ****************** QueueGetConfigRes ********************
def parse_QueueGetConfigRes(pkt):
    queue_raw = pkt.this_packet[0:8]
    queue = unpack('!H6s', queue_raw)
    queueConfRes = {'port': queue[0], 'pad': queue[1]}

    pkt.prepare_printing('print_queueRea', queueConfRea)

    start = 8
    while (pkt.this_packet[start:] > 0):
        # Queues - it could be multiple
        # queue_id(32), length(16), pad(16)
        queue_raw = pkt.this_packet[start:start+8]
        queue = unpack('!LHH', queue_raw)
        queues = {'queue_id': queue[0], 'length': queue[1], 'pad': queue[2]}
        of10.prints.print_queues(queues)

        q_start = start + 8

        # Look of properties
        # property(16), length(16), pad(32), rate(16), pad(48)
        properties = pkt.this_packet[q_start:q_start+queues['length']-8]

        while (len(properties[q_start:]) > 0):
            prop_raw = pkt.this_packet[q_start:q_start+8]
            prop = unpack('!HHLH6s', prop_raw)
            properties = {'type': prop[0], 'length': prop[1],
                          'pad': prop[2], 'rate': prop[3], 'pad2': prop[4]}
            of10.prints.print_queueRes_properties(properties)

        start = start + queues['length']

    return 1
