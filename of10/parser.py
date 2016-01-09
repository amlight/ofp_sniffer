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
    of_type = pkt.of_h['type']
    of_xid = pkt.of_h['xid']
    print_options = pkt.print_options
    h_size = 0
    packet = pkt.this_packet

    if of_type == 0:
        result = parse_Hello(pkt)
    elif of_type == 1:
        result = parse_Error(pkt)
    elif of_type == 2:
        result = parse_EchoReq(pkt)
    elif of_type == 3:
        result = parse_EchoRes(pkt)
    elif of_type == 4:
        result = parse_Vendor(packet, h_size, of_xid)
    elif of_type == 5:
        result = parse_FeatureReq(pkt)
    elif of_type == 6:
        result = parse_FeatureRes(packet, h_size, of_xid)
    elif of_type == 7:
        result = parse_GetConfigReq(packet, h_size, of_xid)
    elif of_type == 8:
        result = parse_GetConfigRes(packet, h_size, of_xid)
    elif of_type == 9:
        result = parse_SetConfig(packet, h_size, of_xid)
    elif of_type == 10:
        result = parse_PacketIn(pkt)
    elif of_type == 11:
        result = parse_FlowRemoved(packet, h_size, of_xid)
    elif of_type == 12:
        result = parse_PortStatus(packet, h_size, of_xid)
    elif of_type == 13:
        result = parse_PacketOut(pkt)
    elif of_type == 14:
        result = parse_FlowMod(packet, h_size, of_xid, print_options)
    elif of_type == 15:
        result = parse_PortMod(packet, h_size, of_xid)
#    elif of_type == 16:
#        result = parse_StatsReq(packet, h_size, of_xid)
#    elif of_type == 17:
#        result = parse_StatsRes(packet, h_size, of_xid)
    elif of_type == 18:
        result = parse_BarrierReq(pkt)
    elif of_type == 19:
        result = parse_BarrierRes(pkt)
    elif of_type == 20:
        result = parse_QueueGetConfigReq(packet, h_size, of_xid)
    elif of_type == 21:
        result = parse_QueueGetConfigRes(packet, h_size, of_xid)
    else:
        return 0
    return result


# *************** Hello *****************
def parse_Hello(pkt):
    pkt.prepare_printing('print_of_hello', None)
    pkt.print_packet()
    return 1


# ************** Error *****************
def parse_Error(pkt):
    of_error = pkt.this_packet[0:4]
    ofe = unpack('!HH', of_error)

    error = {'type': ofe[0], 'code': ofe[1]}
    pkt.prepare_printing('print_of_error', error)
    pkt.print_packet()
    return 1


# ************ EchoReq *****************
def parse_EchoReq(pkt):
    pkt.prepare_printing('print_echoreq', None)
    pkt.print_packet()
    return 1


# ************ EchoRes *****************
def parse_EchoRes(pkt):
    pkt.prepare_printing('print_echores', None)
    pkt.print_packet()
    return 1


# ************ Vendor ******************
def parse_Vendor(packet, h_size, of_xid):
    of_vendor = packet[h_size:h_size+4]
    ofv = unpack('!L', of_vendor)
    of10.prints.print_of_vendor(ofv[0], of_xid)

    # If code 8992 = NICIRA
    if ofv[0] == 8992:
        of10.vendors.parse_nicira(packet, h_size+4, of_xid)
    print
    return 1


# *********** FeatureReq ***************
def parse_FeatureReq(pkt):
    pkt.prepare_printing('print_of_feature_req', None)
    pkt.print_packet()
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


def _parse_phy_ports(packet, of_xid):
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


def parse_FeatureRes(packet, h_size, of_xid):
    of_fres = packet[h_size:h_size+24]
    ofrs = unpack('!8sLB3sLL', of_fres)
    f_res = {'datapath_id': ofrs[0], 'n_buffers': ofrs[1], 'n_tbls': ofrs[2],
             'pad': ofrs[3]}
    of10.prints.print_of_feature_res(of_xid, f_res)

    # 'capabilities': ofrs[4], 'actions': ofrs[5]}
    caps = []
    caps = _parse_capabilities(ofrs[4])
    actions = []
    actions = _parse_actions(ofrs[5])
    of10.prints.print_of_feature_res_caps_and_actions(of_xid, caps, actions)

    # Ports description?
    start = h_size + 24
    while len(packet[start:]) > 0:
        ports = _parse_phy_ports(packet[start:start+48], of_xid)
        of10.prints.print_of_feature_res_ports(of_xid, ports)
        start = start + 48

    return 1


# ***************** GetConfigReq *********************
def parse_GetConfigReq(packet, h_size, of_xid):
    of10.prints.print_of_getconfig_req(of_xid)
    return 1


# ***************** GetConfigRes ********************
def _parse_SetGetConfig(packet, h_size):
    pkt_raw = packet[h_size:h_size+4]
    pkt_list = unpack('!HH', pkt_raw)
    flag = of10.dissector.get_configres_flags(pkt_list[0])
    miss_send_len = pkt_list[1]
    return flag, miss_send_len


def parse_GetConfigRes(packet, h_size, of_xid):
    flag, miss_send_len = _parse_SetGetConfig(packet, h_size)
    of10.prints.print_ofp_getConfigRes(of_xid, flag, miss_send_len)
    return 1


# ******************* SetConfig **********************
def parse_SetConfig(packet, h_size, of_xid):
    flag, miss_send_len = _parse_SetGetConfig(packet, h_size)
    of10.prints.print_ofp_setConfig(of_xid, flag, miss_send_len)
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
        pkt.prepare_printing('print_arp', arp)
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


# def parse_PacketIn(packet, h_size, of_xid, sanitizer):
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

    pkt.print_packet()

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
def parse_FlowRemoved(packet, h_size, of_xid):
    ofmatch = _parse_OFMatch(packet, h_size)
    of10.prints.print_ofp_match(of_xid, ofmatch)

    of_rem_body = packet[h_size+40:h_size+40+40]
    ofrem = unpack('!QHBBLLHBBQQ', of_rem_body)
    cookie = ofrem[0] if ofrem[0] > 0 else 0
    cookie = '0x' + format(cookie, '02x')
    reason = of10.dissector.get_flow_removed_reason(ofrem[2])

    ofrem = {'cookie': cookie, 'priority': ofrem[1], 'reason': reason,
             'pad': ofrem[3], 'duration_sec': ofrem[4],
             'duration_nsec': ofrem[5], 'idle_timeout': ofrem[6],
             'pad2': ofrem[7], 'pad3': ofrem[8],
             'packet_count': ofrem[9], 'byte_count': ofrem[10]}

    of10.prints.print_ofp_flow_removed(of_xid, ofrem)
    return 1


# ******************* PortStatus *****************************
def parse_PortStatus(packet, h_size, of_xid):
    port_raw = packet[h_size:h_size+8]
    port = unpack('!B7s', port_raw)
    reason = of10.dissector.get_portStatus_reason(port[0])
    pad = port[1]
    of10.prints.print_portStatus(of_xid, reason, pad)
    ports = _parse_phy_ports(packet[h_size+8:h_size+64], of_xid)
    of10.prints.print_of_feature_res_ports(of_xid, ports)
    return 1


# ******************* PacketOut *****************************
def parse_PacketOut(pkt):
    # buffer_id(32), in_port(16), actions_len(16)
    pkt_raw = pkt.this_packet[0:8]
    p_out = unpack('!LHH', pkt_raw)
    actions_len = p_out[2]
    packetOut = {'buffer_id': p_out[0], 'in_port': p_out[1],
                 'actions_len': actions_len}

    pkt.prepare_printing('print_packetOut', packetOut)
    # Actions
    start = 8
    _parse_OFAction(pkt.this_packet[start:start+packetOut['actions_len']], 0)
    # Ethernet
    start = 8 + packetOut['actions_len']
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

    pkt.print_packet()
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
        ofmatch = {'wildcards': '4194303'}
        return ofmatch
    elif wildcard == 0:
        ofmatch = {'wildcards': '0'}
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


def _parse_OFAction(packet, start, ofactions=[]):
    '''
        Actions
    '''
    # Actions: Header = 4 , plus each possible action
    # Payload varies:
    #  4 for types 0,1,2,6,7,8,9,a,ffff
    #  0 for type 3
    #  12 for types 4,5,b
    action_header = 4
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

            ofa_temp = of10.prints.print_ofp_action(ofa_type,
                                                    ofa_length,
                                                    ofa_action_payload)

            # Print OVS format
            ofactions.append(ofa_temp)
            ofactions.append(',')
            # Next packet would start at..
            start = start + total_length
        else:
            break

    return ofactions


def parse_FlowMod(packet, h_size, of_xid, print_options):

    ofmatch = _parse_OFMatch(packet, h_size)
    of10.prints.print_ofp_match(of_xid, ofmatch)

    ofbody = _parse_OFBody(packet, h_size)
    of10.prints.print_ofp_body(of_xid, ofbody)

    if ofbody['command'] == 3:
        ovs_command = 'del-flows'
    else:
        ovs_command = 'add-flow'

    # Print OVS
    ofactions = []
    ofactions.append("action=")

    # Actions: Header = 4 , plus each possible action
    # Payload varies:
    #  4 for types 0,1,2,6,7,8,9,a,ffff
    #  0 for type 3
    #  12 for types 4,5,b
    start = h_size+64

    ofactions = _parse_OFAction(packet, start, ofactions)

    if print_options['ovs'] == 1:
        of10.prints.print_ofp_ovs(print_options, ofmatch, ofactions,
                                  ovs_command, ofbody['priority'])
    return 1


# ********************* PortMod ****************************
def parse_PortMod(packet, h_size, of_xid):
    # port(16), hw_addr(48), config(32), mask(32), advertise(32), pad(32)
    pmod_raw = packet[h_size:h_size+24]
    pmod = unpack('!H6sLLLL', pmod_raw)

    config = _parse_phy_config(pmod[2])
    mask = _parse_phy_config(pmod[3])
    advertise = _parse_phy_curr(pmod[4])
    portMod = {'port': pmod[0], 'hw_addr': pmod[1], 'config': config,
               'mask': mask, 'advertise': advertise, 'pad': pmod[5]}

    of10.prints.print_PortMod(of_xid, portMod)
    return 1


# ******************** StatReq ****************************
def parse_StatsReq(packet, h_size, of_xid):
    '''
        Process the StatsReq
    '''
    # Get type = 16bits
    # Get flags = 16bits
    of_stat_req = packet[h_size:h_size+4]
    ofstat = unpack('!HH', of_stat_req)
    stat_type = ofstat[0]
    # FLags were not defined yet. Ignoring.
    # flags = ofstat[1]
    start = h_size+4

    # 7 Types available
    if stat_type == 0:
        # Description
        # No extra fields
        of10.prints.print_ofp_statReqDesc(of_xid, stat_type)

    elif stat_type == 1 or stat_type == 2:
        # Flow(1) or Aggregate(2)
        # Fields: match(40), table_id(8), pad(8), out_port(16)
        of_match = _parse_OFMatch(packet, start)
        # 44 Bytes (40B from Match, 4 from header)
        of_stat_req = packet[start+40:start+40+4]
        ofstat = unpack('!BBH', of_stat_req)
        table_id = ofstat[0]
        pad = ofstat[1]
        out_port = ofstat[2]
        of10.prints.print_ofp_statReqFlowAggregate(of_xid, stat_type,
                                                   of_match, table_id, pad,
                                                   out_port)
    elif stat_type == 3:
        # Table
        # No extra fields
        of10.prints.print_ofp_statReqTable(of_xid, stat_type)

    elif stat_type == 4:
        # Port
        # Fields: port_number(16), pad(48)
        of_stat_req = packet[start:start+8]
        ofstat = unpack('!H6s', of_stat_req)
        port_number = ofstat[0]
        pad = ofstat[1]
        of10.prints.print_ofp_statReqPort(of_xid, stat_type, port_number,
                                          pad)

    elif stat_type == 5:
        # Queue
        # Fields: port_number(16), pad(16), queue_id(32)
        of_stat_req = packet[start:start+8]
        ofstat = unpack('!HHL', of_stat_req)
        port_number = ofstat[0]
        pad = ofstat[1]
        queue_id = ofstat[2]
        of10.prints.print_ofp_statReqQueue(of_xid, stat_type, port_number,
                                           pad, queue_id)
    elif stat_type == 65535:
        # Vendor
        # Fields: vendor_id(32) + data
        of_stat_req = packet[start:start+4]
        ofstat = unpack('!L', of_stat_req)
        vendor_id = ofstat[0]
        of10.prints.print_ofp_statReqVendor(of_xid, stat_type, vendor_id)

    else:
        print ('%s StatReq: Unknown Type: %s' % (of_xid, stat_type))
        return 0
    return 1


# *********************** StatsRes ****************************
# Actions need to be handled
def parse_StatsRes(packet, h_size, of_xid):
    # Get type = 16bits
    # Get flags = 16bits
    of_stat_req = packet[h_size:h_size+4]
    ofstat = unpack('!HH', of_stat_req)
    stat_type = ofstat[0]
    # flags = ofstat[1]
    start = h_size+4

    # 7 Types available
    if stat_type == 0:
        # Description
        # Fields: mfr_desc(2048), hw_desc(2048), sw_desc(2048), serial_num(256),
        #  dp_desc(2048)
        desc_raw = packet[start:start+1056]
        desc = unpack('!256s256s256s32s256s', desc_raw)
        mfr_desc = desc[0]
        hw_desc = desc[1]
        sw_desc = desc[2]
        serial_num = desc[3]
        dp_desc = desc[4]
        of10.prints.print_ofp_statResDesc(of_xid, stat_type, mfr_desc,
                                          hw_desc, sw_desc, serial_num,
                                          dp_desc)

    elif stat_type == 1:
        # Flow(1)
        # Fields: length(16), table_id(8), pad(8), match(40), duration_sec(32),
        #  duration_nsec(32), priority(16), idle_timeout(16), hard_timeout(16),
        #  pad(48), cookie(64), packet_count(64), byte_count(64), actions[]
        count = len(packet[h_size:]) - 4
        while (count > 0):
            flow_raw = packet[start:start+4]
            flow = unpack('!HBB', flow_raw)
            res_flow = {'length': flow[0], 'table_id': flow[1], 'pad': flow[2]}
            of_match = _parse_OFMatch(packet, start+4)
            flow_raw = packet[start+44:start+44+44]
            flow = unpack('!LLHHH6sQQQ', flow_raw)
            res_flow.update({'duration_sec': flow[0], 'duration_nsec': flow[1],
                             'priority': flow[2], 'idle_timeout': flow[3],
                             'hard_timeout': flow[4], 'pad2': flow[5],
                             'cookie': flow[6], 'packet_count': flow[7],
                             'byte_count': flow[8]})

            of10.prints.print_ofp_statResFlow(of_xid, stat_type, of_match,
                                              res_flow)
            # Process Actions[]
            end = res_flow['length'] - (4 + 40 + 44)
            actions = packet[start+88:start+88+end]
            _parse_OFAction(actions, 0)

            count = count - int(res_flow['length'])
            start = start + int(res_flow['length'])

    elif stat_type == 2:
        # Aggregate(2)
        # Fields: packet_count(64), byte_count(64), flow_count(32), pad(32)
        flow_raw = packet[start:start+24]
        flow = unpack('!QQLL', flow_raw)
        res_flow = {'packet_count': flow[0], 'byte_count': flow[1],
                    'flow_count': flow[2], 'pad': flow[3]}
        of10.prints.print_ofp_statResAggregate(of_xid, stat_type, res_flow)

    elif stat_type == 3:
        # Table
        # Fields: table_id(8), pad(24), name(256), wildcards(32),
        #  max_entries(32), active_count(32), lookup_count(64),
        #  matched_count(64)
        flow_raw = packet[start:start+64]
        flow = unpack('!B3s32sLLLQQ', flow_raw)
        res_flow = {'table_id': flow[0], 'pad': flow[1], 'name': flow[2],
                    'wildcards': flow[3], 'max_entries': flow[4],
                    'active_count': flow[5], 'lookup_count': flow[6],
                    'matched_count': flow[7]}
        of10.prints.print_ofp_statResTable(of_xid, stat_type, res_flow)

    elif stat_type == 4:
        # Port
        # Fields: port_number(16), pad(48), rx_packets(64), tx_packets(64),
        #  rx_bytes(64), tx_bytes(64), rx_dropped(64), tx_dropped(64),
        #  rx_errors(64), tx_errors(64), rx_frame_err(64), rx_over_err(64),
        #  rx_crc_err(64), collisions(64)
        count = len(packet[h_size:]) - 4
        while (count > 0):
            flow_raw = packet[start:start+104]
            flow = unpack('!H6sQQQQQQQQQQQQ', flow_raw)
            res_flow = {'port_number': flow[0], 'pad': flow[1],
                        'rx_packets': flow[2], 'tx_packets': flow[3],
                        'rx_bytes': flow[4], 'tx_bytes': flow[5],
                        'rx_dropped': flow[6], 'tx_dropped': flow[7],
                        'rx_errors': flow[8], 'tx_errors': flow[9],
                        'rx_frame_err': flow[10], 'rx_over_err': flow[11],
                        'rx_crc_err': flow[12], 'collisions': flow[13]}
            of10.prints.print_ofp_statResPort(of_xid, stat_type, res_flow)

            count = count - 104
            start = start + 104

    elif stat_type == 5:
        # Queue
        # Fields: length(16), pad(16), queue_id(32), tx_bytes(64),
        #  tx_packets(64), tx_errors(64)
        count = len(packet[h_size:]) - 4
        while (count > 0):
            flow_raw = packet[start:start+32]
            flow = unpack('!HHLQQQ', flow_raw)
            res_flow = {'length': flow[0], 'pad': flow[1], 'queue_id': flow[2],
                        'tx_bytes': flow[3], 'tx_packets': flow[4],
                        'tx_errors': flow[5]}
            of10.prints.print_ofp_statResQueue(of_xid, stat_type, res_flow)
            count = count - 32
            start = start + 32
        else:
            print ('%s StatRes Type: Queue(%s)' % (of_xid, stat_type))
            print ('%s No Queues' % (of_xid))

    elif stat_type == 65535:
        # Vendor
        # Fields: vendor_id(32), data(?)
        flow_raw = packet[start:start+4]
        flow = unpack('!L', flow_raw)
        res_flow = {'vendor_id': flow[0]}
        of10.prints.print_ofp_statResVendor(of_xid, stat_type, res_flow)

        start = start + 4
        data = []
        count = len(packet[h_size:])
        while (start < count):
            flow_raw = packet[start:start+1]
            flow = unpack('!B', flow_raw)
            data.append(str(flow[0]))
            start = start + 1
        of10.prints.print_ofp_statResVendorData(of_xid, ''.join(data))

    else:
        print ('%s StatRes: Unknown Type: %s' % (of_xid, stat_type))
        return 0
    return 1


# ********************** BarrierReq ***********************
def parse_BarrierReq(pkt):
    pkt.prepare_printing('print_of_BarrierReq', None)
    pkt.print_packet()
    return 1


# ********************** BarrierRes ***********************
def parse_BarrierRes(pkt):
    pkt.prepare_printing('print_of_BarrierReply', None)
    pkt.print_packet()
    return 1


# ******************* QueueGetConfigReq *******************
def parse_QueueGetConfigReq(packet, h_size, of_xid):
    queue_raw = packet[h_size:h_size+4]
    queue = unpack('!HH', queue_raw)
    queueConfReq = {'port': queue[0], 'pad': queue[1]}
    of10.prints.print_queueReq(of_xid, queueConfReq)
    return 1


# ****************** QueueGetConfigRes ********************
def parse_QueueGetConfigRes(packet, h_size, of_xid):
    queue_raw = packet[h_size:h_size+8]
    queue = unpack('!H6s', queue_raw)
    queueConfRes = {'port': queue[0], 'pad': queue[1]}

    of10.prints.print_queueRes(of_xid, queueConfRes)

    start = h_size + 8
    while (packet[start:] > 0):
        # Queues - it could be multiple
        # queue_id(32), length(16), pad(16)
        queue_raw = packet[start:start+8]
        queue = unpack('!LHH', queue_raw)
        queues = {'queue_id': queue[0], 'length': queue[1], 'pad': queue[2]}
        of10.prints.print_queues(of_xid, queues)

        q_start = start + 8

        # Look of properties
        # property(16), length(16), pad(32), rate(16), pad(48)
        properties = packet[q_start:q_start+queues['length']-8]

        while (len(properties[q_start:]) > 0):
            prop_raw = packet[q_start:q_start+8]
            prop = unpack('!HHLH6s', prop_raw)
            properties = {'type': prop[0], 'length': prop[1],
                          'pad': prop[2], 'rate': prop[3], 'pad2': prop[4]}
            of10.prints.print_queueRes_properties(of_xid, properties)

        start = start + queues['length']

    return 1
