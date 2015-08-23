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


def _parse_OFMatch(packet, h_size):
    of_match = packet[h_size:h_size+40]
    ofm = unpack('!LH6s6sHBBHBBHLLHH', of_match)
    ofm_wildcards = ofm[0]
    ofm_in_port = ofm[1]
    ofm_dl_src = ofm[2]
    ofm_dl_dst = ofm[3]
    ofm_dl_vlan = ofm[4]
    ofm_pcp = ofm[5]
    ofm_pad = ofm[6]
    ofm_dl_type = ofm[7]
    ofm_nw_tos = ofm[8]
    ofm_nw_prot = ofm[9]
    ofm_pad2 = ofm[10]
    ofm_nw_src = ofm[11]
    ofm_nw_dst = ofm[12]
    ofm_tp_src = ofm[13]
    ofm_tp_dst = ofm[14]

    return (ofm_wildcards, ofm_in_port, ofm_dl_src, ofm_dl_dst, ofm_dl_vlan,
            ofm_pcp, ofm_pad, ofm_dl_type, ofm_nw_tos, ofm_nw_prot, ofm_pad2,
            ofm_nw_src, ofm_nw_dst, ofm_tp_src, ofm_tp_dst)


def _parse_OFBody(packet, h_size):
    of_mod_body = packet[h_size+40:h_size+40+24]
    ofmod = unpack('!8sHHHHLHH', of_mod_body)
    ofmod_cookie = ofmod[0] if not len(ofmod[0]) else 0
    ofmod_command = ofmod[1]
    ofmod_idle_timeout = ofmod[2]
    ofmod_hard_timeout = ofmod[3]
    ofmod_prio = ofmod[4]
    ofmod_buffer_id = ofmod[5]
    ofmod_out_port = ofmod[6]
    ofmod_flags = ofmod[7]

    return (ofmod_cookie, ofmod_command, ofmod_idle_timeout, ofmod_idle_timeout,
            ofmod_hard_timeout, ofmod_prio, ofmod_buffer_id, ofmod_out_port,
            ofmod_flags)


def parse_FlowMod(packet, h_size, of_xid):

    (ofm_wildcards, ofm_in_port, ofm_dl_src, ofm_dl_dst, ofm_dl_vlan, ofm_pcp,
        ofm_pad, ofm_dl_type, ofm_nw_tos, ofm_nw_prot, ofm_pad2, ofm_nw_src,
        ofm_nw_dst, ofm_tp_src, ofm_tp_dst) = _parse_OFMatch(packet, h_size)

    ofp_prints_v10.print_ofp_match(of_xid, ofm_wildcards, ofm_in_port,
                                   ofm_dl_src, ofm_dl_dst,
                                   ofm_dl_vlan, ofm_dl_type, ofm_pcp,
                                   ofm_pad, ofm_nw_tos, ofm_nw_prot,
                                   ofm_pad2, ofm_nw_src, ofm_nw_dst,
                                   ofm_tp_src, ofm_tp_dst)

    (ofmod_cookie, ofmod_command, ofmod_idle_timeout, ofmod_idle_timeout,
     ofmod_hard_timeout, ofmod_prio, ofmod_buffer_id, ofmod_out_port,
     ofmod_flags) = _parse_OFBody(packet, h_size)

    ofp_prints_v10.print_ofp_body(of_xid, ofmod_cookie, ofmod_command,
                                  ofmod_idle_timeout,
                                  ofmod_hard_timeout,
                                  ofmod_prio, ofmod_buffer_id,
                                  ofmod_out_port, ofmod_flags)

    # Actions: Header, Port plus each possible
    start = h_size+64
    while (1):
        ofp_action = packet[start:start+4]
        if len(ofp_action) > 0:
            ofa = unpack('!HH', ofp_action)
            ofa_type = ofa[0]
            ofa_length = ofa[1]
            ofa_action_payload = packet[start+4:start+8]
            ofp_prints_v10.print_ofp_action(of_xid, ofa_type, ofa_length,
                                            ofa_action_payload)
            start = start + 4
        else:
            break
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
