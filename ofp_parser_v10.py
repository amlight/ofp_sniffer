from struct import unpack
import ofp_dissector_v10
import ofp_prints_v10


def process_ofp_type(of_type, packet, h_size, of_xid):
    if of_type == 0:
        result = parse_Hello(packet, h_size, of_xid)
    elif of_type == 1:
        result = parse_Error(packet, h_size, of_xid)
    elif of_type == 2:
        result = parse_EchoReq(packet, h_size, of_xid)
    elif of_type == 3:
        result = parse_EchoRes(packet, h_size, of_xid)
    elif of_type == 4:
        result = parse_Vendor(packet, h_size, of_xid)
    elif of_type == 5:
        result = parse_FeatureReq(packet, h_size, of_xid)
    elif of_type == 6:
        result = parse_FeatureRes(packet, h_size, of_xid)
    elif of_type == 7:
        result = parse_GetConfigReq(packet, h_size, of_xid)
    elif of_type == 8:
        result = parse_GetConfigRes(packet, h_size, of_xid)
    elif of_type == 9:
        result = parse_SetConfig(packet, h_size, of_xid)
    elif of_type == 10:
        result = parse_PacketIn(packet, h_size, of_xid)
    elif of_type == 11:
        result = parse_FlowRemoved(packet, h_size, of_xid)
    elif of_type == 12:
        result = parse_PortStatus(packet, h_size, of_xid)
    elif of_type == 13:
        result = parse_PacketOut(packet, h_size, of_xid)
    elif of_type == 14:
        result = parse_FlowMod(packet, h_size, of_xid)
    elif of_type == 15:
        result = parse_PortMod(packet, h_size, of_xid)
    elif of_type == 16:
        result = parse_StatsReq(packet, h_size, of_xid)
    elif of_type == 17:
        result = parse_StatsRes(packet, h_size, of_xid)
    elif of_type == 18:
        result = parse_BarrierReq(packet, h_size, of_xid)
    elif of_type == 19:
        result = parse_BarrierRes(packet, h_size, of_xid)
    elif of_type == 20:
        result = parse_QueueGetConfigReq(packet, h_size, of_xid)
    elif of_type == 21:
        result = parse_QueueGetConfigRes(packet, h_size, of_xid)
    else:
        return 0
    return result


def parse_Hello(packet, h_size, of_xid):
    ofp_prints_v10.print_of_hello(of_xid)
    return 1


def parse_Error(packet, h_size, of_xid):
    of_error = packet[h_size:h_size+4]
    ofe = unpack('!HH', of_error)
    ofe_type = ofe[0]
    ofe_code = ofe[1]

    nameCode, typeCode = ofp_dissector_v10.get_ofp_error(ofe_type, ofe_code)
    ofp_prints_v10.print_of_error(of_xid, nameCode, typeCode)
    return 1


def parse_EchoReq(packet, h_size, of_xid):
    return 0


def parse_EchoRes(packet, h_size, of_xid):
    return 0


def parse_Vendor(packet, h_size, of_xid):
    return 0


def parse_FeatureReq(packet, h_size, of_xid):
    return 0


def parse_FeatureRes(packet, h_size, of_xid):
    return 0


def parse_GetConfigReq(packet, h_size, of_xid):
    return 0


def parse_GetConfigRes(packet, h_size, of_xid):
    return 0


def parse_SetConfig(packet, h_size, of_xid):
    return 0


def parse_PacketIn(packet, h_size, of_xid):
    # It won't be created
    return 1


def parse_FlowRemoved(packet, h_size, of_xid):

    (ofm_wildcards, ofm_in_port, ofm_dl_src, ofm_dl_dst, ofm_dl_vlan, ofm_pcp,
     ofm_pad, ofm_dl_type, ofm_nw_tos, ofm_nw_prot, ofm_pad2, ofm_nw_src,
     ofm_nw_dst, ofm_tp_src, ofm_tp_dst) = _parse_OFMatch(packet, h_size)

    ofp_prints_v10.print_ofp_match(of_xid, ofm_wildcards, ofm_in_port,
                                   ofm_dl_src, ofm_dl_dst,
                                   ofm_dl_vlan, ofm_dl_type, ofm_pcp,
                                   ofm_pad, ofm_nw_tos, ofm_nw_prot,
                                   ofm_pad2, ofm_nw_src, ofm_nw_dst,
                                   ofm_tp_src, ofm_tp_dst)

    of_rem_body = packet[h_size+40:h_size+40+40]
    ofrem = unpack('!8sHBBLLHBB8s8s', of_rem_body)
    ofrem_cookie = ofrem[0] if not len(ofrem[0]) else 0
    ofrem_priority = ofrem[1]
    ofrem_reason = ofrem[2]
    ofrem_pad = ofrem[3]
    ofrem_duration_sec = ofrem[4]
    ofrem_duration_nsec = ofrem[5]
    ofrem_idle_timeout = ofrem[6]
    ofrem_pad2 = ofrem[7]
    ofrem_pad3 = ofrem[8]
    ofrem_packet_count = ofrem[9]
    ofrem_byte_count = ofrem[10]

    ofp_prints_v10.print_ofp_flow_removed(of_xid, ofrem_cookie, ofrem_priority,
                                          ofrem_reason, ofrem_pad,
                                          ofrem_duration_sec,
                                          ofrem_duration_nsec,
                                          ofrem_idle_timeout,
                                          ofrem_pad2, ofrem_pad3,
                                          ofrem_packet_count,
                                          ofrem_byte_count)
    return 1


def parse_PortStatus(packet, h_size, of_xid):
    return 0


def parse_PacketOut(packet, h_size, of_xid):
    # It won't be created
    return 1


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
                1048576: 'pcp',
                2097152: 'nw_tos'}

    return wildcard.get(wcard)


def _parse_OFMatch(packet, h_size):
    of_match = packet[h_size:h_size+40]
    ofm = unpack('!LH6s6sHBBHBBHLLHH', of_match)
    wildcard = ofm[0]
    dl_src = ofp_prints_v10.eth_addr(ofm[2])
    dl_dst = ofp_prints_v10.eth_addr(ofm[3])

    ofmatch = {'wildcards': ofm[0], 'in_port': ofm[1], 'dl_src': dl_src,
               'dl_dst': dl_dst, 'dl_vlan': ofm[4], 'pcp': ofm[5],
               'dl_type': ofm[7], 'nw_tos': ofm[8], 'nw_prot': ofm[9],
               'nw_src': ofm[11], 'nw_dst': ofm[12], 'tp_src': ofm[13],
               'tp_dst': ofm[14]}

    if wildcard == ((1 << 22) - 1):
        ofmatch = {}
        return ofmatch
    else:
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
    ofmod = unpack('!8sHHHHLHH', of_mod_body)
    ofmod_cookie = ofmod[0] if not len(ofmod[0]) else 0

    ofbody = {'cookie': ofmod_cookie, 'command': ofmod[1],
              'idle_timeout': ofmod[2], 'hard_timeout': ofmod[3],
              'priority': ofmod[4], 'buffer_id': ofmod[5],
              'buffer_id': ofmod[5], 'out_port': ofmod[6],
              'flags': ofmod[7]}
    return ofbody


def parse_FlowMod(packet, h_size, of_xid):

    ofmatch = _parse_OFMatch(packet, h_size)
    ofp_prints_v10.print_ofp_match(of_xid, ofmatch)

    ofbody = _parse_OFBody(packet, h_size)
    # ofp_prints_v10.print_ofp_body(ofbody)

    # Actions: Header = 4 , plus each possible action
    # Payload varies:
    #  4 for types 0,1,2,6,7,8,9,a,ffff
    #  0 for type 3
    #  12 for types 4,5,b
    start = h_size+64
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

            ofp_prints_v10.print_ofp_action(of_xid, ofa_type, ofa_length,
                                            ofa_action_payload)
            # Next packet would start at..
            start = start + total_length
        else:
            return 1
    return 1


def parse_PortMod(packet, h_size, of_xid):
    return 0


def parse_StatsReq(packet, h_size, of_xid):
    return 0


def parse_StatsRes(packet, h_size, of_xid):
    return 0


def parse_BarrierReq(packet, h_size, of_xid):
    return 0


def parse_BarrierRes(packet, h_size, of_xid):
    return 0


def parse_QueueGetConfigReq(packet, h_size, of_xid):
    return 0


def parse_QueueGetConfigRes(packet, h_size, of_xid):
    return 0
