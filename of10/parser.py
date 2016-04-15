"""
   Parser for OpenFlow 1.0
"""

import socket
import struct
from struct import unpack
import gen.proxies
import gen.tcpip
import of10.dissector
import of10.prints
import of10.vendors

from of10.packet import OFP_Action
from of10.packet import OFP_Phy_port
from of10.packet import OFP_Match
from of10.packet import OFP_STAT_FLOW
from of10.packet import OFP_STAT_PORT
from of10.packet import OFP_STAT_QUEUE
from of10.packet import OFP_QUEUE, OFP_QUEUE_PROPERTIES, OFP_QUEUE_PROP_PAYLOAD


# *************** Hello *****************
def parse_Hello(msg, packet):
    msg.data = packet


# ************** Error *****************
def parse_Error(msg, packet):
    of_error = packet[0:4]
    ofe = unpack('!HH', of_error)
    msg.type = ofe[0]
    msg.code = ofe[1]


# ************ EchoReq *****************
def parse_EchoReq(msg, packet):
    msg.data = packet


# ************ EchoRes *****************
def parse_EchoRes(msg, packet):
    msg.data = packet


# ************ Vendor ******************
def parse_Vendor(msg, packet):
    of_vendor = packet[0:4]
    ofv = unpack('!L', of_vendor)
    msg.vendor = ofv[0]
    msg.data = packet[4:]


# *********** FeatureReq ***************
def parse_FeatureReq(msg, packet):
    pass


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

    port = OFP_Phy_port()
    port.port_id = port_id
    port.hw_addr = hw_addr
    port.name = phy[2]
    port.config = config
    port.state = state
    port.curr = curr
    port.advertised = advertised
    port.supported = supported
    port.peer = peer
    return port


def parse_FeatureRes(msg, packet):
    of_fres = packet[0:24]
    ofrs = unpack('!8sLB3sLL', of_fres)
    msg.datapath_id = ofrs[0]
    msg.n_buffers = ofrs[1]
    msg.n_tbls = ofrs[2]
    msg.pad = ofrs[3]
    msg.capabilities = _parse_capabilities(ofrs[4])
    msg.actions = _parse_actions(ofrs[5])

    # Ports description?
    start = 24
    ports_array = []
    while len(packet[start:]) > 0:
        port = _parse_phy_ports(packet[start:start+48])
        ports_array.append(port)
        start = start + 48
    msg.ports = ports_array
    return 1


# ***************** GetConfigReq *********************
def parse_GetConfigReq(msg, packet):
    pass


# ***************** GetConfigRes ********************
def _parse_SetGetConfig(packet, h_size):
    pkt_raw = packet[h_size:h_size+4]
    pkt_list = unpack('!HH', pkt_raw)
    flags = of10.dissector.get_configres_flags(pkt_list[0])
    return flags, pkt_list[1]


def parse_GetConfigRes(msg, packet):
    msg.flags, msg.miss_send_len = _parse_SetGetConfig(packet, 0)


# ******************* SetConfig **********************
def parse_SetConfig(msg, packet):
    msg.flags, msg.miss_send_len = _parse_SetGetConfig(packet, 0)


# ****************** PacketIn ************************
def process_data(pkt, start):
    '''
        This funcion aims to dissect PacketIn and PacketOut data
        It assumes it is
        Ethernet [vlan] (BDDP|LLDP|ARP|IP) [TCP|UDP]
    '''

    # Ethernet
    eth = gen.tcpip.get_ethernet_frame(pkt.packet[start:start+14], 1)
    pkt.prepare_printing('print_layer2_pktIn', eth)

    # VLAN or not - ETYPE 0x8100 or 33024
    start = start + 14
    etype = '0x0000'
    vlan = {}
    if eth['protocol'] in [33024]:
        vlan = gen.tcpip.get_ethernet_vlan(pkt.packet[start:start+2])
        pkt.prepare_printing('print_vlan', vlan)
        start = start + 2
        # If VLAN exists, there is a next eth['protocol']
        etype = gen.tcpip.get_next_etype(pkt.packet[start:start+2])
        start = start + 2
    else:
        etype = eth['protocol']

    # LLDP - ETYPE 0x88CC or 35020
    # BBDP - ETYPE 0x8942 or 35138
    lldp = {}
    if etype in [35020, 35138]:
        lldp = gen.tcpip.get_lldp(pkt.packet[start:])
        if len(lldp) is 0:
            message = {'message': 'LLDP Packet MalFormed'}
            pkt.prepare_printing('print_string', message)
        else:
            pkt.prepare_printing('print_lldp', lldp)
            if pkt.of_h['type'] is 13:
                gen.proxies.support_fsfw(pkt, lldp)
        return

    # OESS FVD - ETYPE 0x88B6 or 34998
    if etype in [34998]:
        message = {'message': 'OESS FVD'}
        pkt.prepare_printing('print_string', message)
        return

    # IP - ETYPE 0x800 or 2048
    if etype in [2048]:
        ip = gen.tcpip.get_ip_packet(pkt.packet, start)
        pkt.prepare_printing('print_layer3', ip)
        if ip['protocol'] is 6:
            tcp = gen.tcpip.get_tcp_stream(pkt.packet, start+ip['length'])
            pkt.prepare_printing('print_tcp', tcp)
        return

    # ARP - ETYPE 0x806 or 2054
    if etype in [2054]:
        arp = gen.tcpip.get_arp(pkt.packet[start:])
        pkt.prepare_printing('print_arp', arp)
        return

    string = 'Ethertype %s not dissected' % hex(eth['protocol'])
    message = {'message': string}
    pkt.prepare_printing('print_string', message)
    return


def parse_PacketIn(msg, packet):
    # buffer_id(32), total_len(16), in_port(16), reason(8), pad(8)
    pkt_raw = packet[0:10]
    p_in = unpack('!LHHBB', pkt_raw)
    reason = of10.dissector.get_packetIn_reason(p_in[3])
    msg.buffer_id = p_in[0]
    msg.total_len = p_in[1]
    msg.in_port = p_in[2]
    msg.reason = reason
    msg.pad = p_in[4]

    # process data
    # how to handle data?
    # process_data(pkt, 10)


# ******************** FlowRemoved ***************************
def parse_FlowRemoved(msg, packet):
    msg.match = _parse_OFMatch(msg, packet, 0)

    of_rem_body = packet[40:40+40]
    ofrem = unpack('!QHBBLLHBBQQ', of_rem_body)
    cookie = ofrem[0] if ofrem[0] > 0 else 0
    cookie = '0x' + format(cookie, '02x')
    reason = of10.dissector.get_flow_removed_reason(ofrem[2])

    msg.cookie = cookie
    msg.priority = ofrem[1]
    msg.reason = reason
    msg.pad = ofrem[3]
    msg.duration_sec = ofrem[4]
    msg.duration_nsec = ofrem[5]
    msg.idle_timeout = ofrem[6]
    msg.pad2 = ofrem[7]
    msg.pad3 = ofrem[8]
    msg.packet_count = ofrem[9]
    msg.byte_count = ofrem[10]


# ******************* PortStatus *****************************
def parse_PortStatus(msg, packet):
    port_raw = packet[0:8]
    port = unpack('!B7s', port_raw)
    reason = of10.dissector.get_portStatus_reason(port[0])
    msg.reason = reason
    msg.pad = port[1]
    msg.desc = _parse_phy_ports(packet[8:64])


# ******************* PacketOut *****************************
def parse_PacketOut(msg, packet):
    # buffer_id(32), in_port(16), actions_len(16)
    pkt_raw = packet[0:8]
    p_out = unpack('!LHH', pkt_raw)
    msg.buffer_id = p_out[0]
    msg.in_port = p_out[1]
    msg.actions_len = p_out[2]

    # Actions
    start = 8
    total = start+msg.actions_len
    msg.action = _parse_OFAction(packet[start:total], 0)

    start = start + msg.actions_len

    # Check if we still have content in the PacketOut
    if len(packet[start:]) == 0:
        return 1

    # process body
    # process_data(pkt, start)

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


def _parse_OFMatch(msg, packet, h_size):
    match_tmp = OFP_Match()
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
        # msg.match.wildcards = 4194303
        match_tmp.wildcards = 4194303
        return match_tmp
    elif wildcard == 0:
        # msg.match.wildcards = 0
        match_tmp.wildcards = 0
        return match_tmp
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

    # Convert from Dict(ofmatch) to Class ofp_match
    # For each item on ofmatch, associate the value to the equivalent on
    # class ofp_match. For example, if there is an ofmatch['in_port']
    # msg.match.inport = ofmatch['in_port']. Others will be None
    require_str = ['dl_src', 'dl_dst', 'nw_src', 'nw_dst']
    for match in ofmatch:
        if match in require_str:
            action = 'match_tmp.%s="%s"'
        else:
            action = 'match_tmp.%s=%s'
        exec (action) % (match, ofmatch.get(match))

    return match_tmp


def _parse_OFBody(msg, packet, h_size):
    of_mod_body = packet[h_size+40:h_size+40+24]
    ofmod = unpack('!QHHHHLHH', of_mod_body)
    ofmod_cookie = ofmod[0] if ofmod[0] > 0 else 0
    ofmod_cookie = '0x' + format(ofmod_cookie, '02x')
    ofmod_buffer_id = '0x' + format(ofmod[5], '02x')

    msg.cookie = ofmod_cookie
    msg.command = ofmod[1]
    msg.idle_timeout = ofmod[2]
    msg.hard_timeout = ofmod[3]
    msg.priority = ofmod[4]
    msg.buffer_id = ofmod_buffer_id
    msg.out_port = ofmod[6]
    msg.flags = ofmod[7]


def get_action(action_type, length, payload):
    # 0 - OUTPUT. Returns port and max_length
    if action_type == 0:
        type_0 = unpack('!HH', payload)
        return type_0[0], type_0[1]
    # 1 - SetVLANID. Returns VID and pad
    elif action_type == 1:
        type_1 = unpack('!H2s', payload)
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
        type_9 = unpack('!H2s', payload)
        return type_9[0], type_9[1]
    # a - SetTPDst
    elif action_type == int('a', 16):
        type_a = unpack('!H2s', payload)
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
            else:
                total_length = 4

            ofa_action_payload = packet[start:start + total_length]
            action = OFP_Action()
            action.type = ofa_type
            action.length = ofa_length
            action.payload = ofa_action_payload
            actions_list.append(action)
            # Next packet would start at..
            start = start + total_length
            del action
        else:
            break

    return actions_list


def parse_FlowMod(msg, packet):
    msg.match = _parse_OFMatch(msg, packet, 0)
    _parse_OFBody(msg, packet, 0)
    # Actions: Header = 4 , plus each possible action
    actions_start = 64
    msg.actions = _parse_OFAction(packet, actions_start)


# ********************* PortMod ****************************
def parse_PortMod(msg, packet):
    # port(16), hw_addr(48), config(32), mask(32), advertise(32), pad(32)
    pmod_raw = packet[0:24]
    pmod = unpack('!H6sLLLL', pmod_raw)

    config = _parse_phy_config(pmod[2])
    mask = _parse_phy_config(pmod[3])
    advertise = _parse_phy_curr(pmod[4])

    msg.port_no = pmod[0]
    msg.hw_addr = pmod[1]
    msg.config = config
    msg.mask = mask
    msg.advertise = advertise
    msg.pad = pmod[5]


# ******************** StatReq ****************************
def parse_StatsReq(msg, packet):
    """ Parse StatReq messages

    Args:
        msg:
        packet:

    Returns:

    """

    # Get type = 16bits
    # Get flags = 16bits
    of_stat_req = packet[0:4]
    ofstat = unpack('!HH', of_stat_req)
    msg.stat_type = ofstat[0]
    msg.flags = ofstat[1]

    start = 4

    # 7 Types available
    if msg.stat_type == 0:
        # Description
        # No extra fields
        pass

    elif msg.stat_type == 1 or msg.stat_type == 2:
        # Flow(1) or Aggregate(2)
        # Fields: match(40), table_id(8), pad(8), out_port(16)
        match = _parse_OFMatch(msg, packet, start)
        # 44 Bytes (40B from Match, 4 from header)
        of_stat_req = packet[start+40:start+40+4]
        table_id, pad, out_port = unpack('!BBH', of_stat_req)
        msg.instantiate(match, table_id, pad, out_port)

    elif msg.stat_type == 3:
        # Table
        # No extra fields
        pass

    elif msg.stat_type == 4:
        # Port
        # Fields: port_number(16), pad(48)
        of_stat_req = packet[start:start+8]
        port_number, pad = unpack('!H6s', of_stat_req)
        msg.instantiate(port_number, pad)

    elif msg.stat_type == 5:
        # Queue
        # Fields: port_number(16), pad(16), queue_id(32)
        of_stat_req = packet[start:start+8]
        port_number, pad, queue_id = unpack('!HHL', of_stat_req)
        msg.instantiate(port_number, pad, queue_id)

    elif msg.stat_type == 65535:
        # Vendor
        # Fields: vendor_id(32) + data
        of_stat_req = packet[start:start+4]
        vendor_id = unpack('!L', of_stat_req)[0]
        msg.instantiate(vendor_id)

    else:
        print 'StatReq: Unknown Type: %s' % msg.stat_type

    return 1


# *********************** StatsRes ****************************
def parse_StatsRes(msg, packet):
    """ Parses OFP_STAT_RES OpenFlow messages

    Args:
        msg: instantiated packet class from of10/packet.py
        packet: OpenFlow message to be processed

    Returns: 1

    """

    # Get type = 16bits - 7 Types available
    # Get flags = 16bits
    of_stat_req = packet[0:4]
    msg.stat_type, msg.flags = unpack('!HH', of_stat_req)

    start = 4

    if msg.stat_type == 0:
        """ Parses Description(0)
            Fields: mfr_desc(2048), hw_desc(2048), sw_desc(2048), serial_num(256),
            dp_desc(2048) = 1056 Bytes
        """
        desc_raw = packet[start:start+1056]
        desc = unpack('!256s256s256s32s256s', desc_raw)
        mfr_desc = desc[0]
        hw_desc = desc[1]
        sw_desc = desc[2]
        serial_num = desc[3]
        dp_desc = desc[4]
        msg.instantiate(mfr_desc, hw_desc, sw_desc, serial_num, dp_desc)

    elif msg.stat_type == 1:
        """ Parses Flow(1)
            Fields: length(16), table_id(8), pad(8), match(40), duration_sec(32),
            duration_nsec(32), priority(16), idle_timeout(16), hard_timeout(16),
            pad(48), cookie(64), packet_count(64), byte_count(64), actions[]
        """
        count = len(packet[0:]) - 4
        flows = []
        while (count > 0):
            flow_raw = packet[start:start+4]
            flow = unpack('!HBB', flow_raw)

            eflow = OFP_STAT_FLOW()

            eflow.length =  flow[0]
            eflow.table_id = flow[1]
            eflow.pad = flow[2]

            eflow.match = _parse_OFMatch(msg, packet, start+4)

            flow_raw = packet[start+44:start+44+44]
            flow = unpack('!LLHHH6sQQQ', flow_raw)

            eflow.duration_sec = flow[0]
            eflow.duration_nsec = flow[1]
            eflow.priority = flow[2]
            eflow.idle_timeout = flow[3]
            eflow.hard_timeout = flow[4]
            eflow.pad2 = flow[5]
            cookie = flow[6] if flow[6] > 0 else 0
            cookie = '0x' + format(cookie, '02x')
            eflow.cookie = cookie
            eflow.packet_count = flow[7]
            eflow.byte_count = flow[8]

            # Process Actions[]
            end = eflow.length - (4 + 40 + 44)
            actions = packet[start+88:start+88+end]
            eflow.actions = _parse_OFAction(actions, 0)

            flows.append(eflow)

            count = count - int(eflow.length)
            start = start + int(eflow.length)
            del eflow

        msg.instantiate(flows)


    elif msg.stat_type == 2:
        """
            Parses Aggregate(2)
            Fields: packet_count(64), byte_count(64), flow_count(32), pad(32) = 24 Bytes
        """
        flow_raw = packet[start:start+24]
        flow = unpack('!QQLL', flow_raw)
        packet_count = flow[0]
        byte_count = flow[1]
        flow_count = flow[2]
        pad = flow[3]
        msg.instantiate(packet_count, byte_count, flow_count, pad)

    elif msg.stat_type == 3:
        """ Parsers Table(3)
            Fields: table_id(8), pad(24), name(256), wildcards(32),
            max_entries(32), active_count(32), lookup_count(64),
            matched_count(64) = 64 Bytes
        """
        flow_raw = packet[start:start+64]
        flow = unpack('!B3s32sLLLQQ', flow_raw)
        table_id = flow[0]
        pad = flow[1]
        name = flow[2]
        wildcards = flow[3]
        max_entries = flow[4]
        active_count = flow[5]
        lookup_count = flow[6]
        matched_count = flow[7]
        msg.instantiate(table_id, pad, name, wildcards, max_entries,
                        active_count, lookup_count, matched_count)

    elif msg.stat_type == 4:
        """ Parses Port(4)
            Fields: port_number(16), pad(48), rx_packets(64), tx_packets(64),
            rx_bytes(64), tx_bytes(64), rx_dropped(64), tx_dropped(64),
            rx_errors(64), tx_errors(64), rx_frame_err(64), rx_over_err(64),
            rx_crc_err(64), collisions(64) = 104 Bytes
        """
        count = len(packet[0:]) - 4
        ports = []
        while (count > 0):
            flow_raw = packet[start:start+104]
            flow = unpack('!H6sQQQQQQQQQQQQ', flow_raw)

            eport = OFP_STAT_PORT()
            eport.port_number = flow[0]
            eport.pad = flow[1]
            eport.rx_packets = flow[2]
            eport.tx_packets = flow[3]
            eport.rx_bytes = flow[4]
            eport.tx_bytes = flow[5]
            eport.rx_dropped = flow[6]
            eport.tx_dropped = flow[7]
            eport.rx_errors = flow[8]
            eport.tx_errors = flow[9]
            eport.rx_frame_err = flow[10]
            eport.rx_over_err = flow[11]
            eport.rx_crc_err = flow[12]
            eport.collisions = flow[13]

            ports.append(eport)
            del eport

            count = count - 104
            start = start + 104

        msg.instantiate(ports)

    elif msg.stat_type == 5:
        """ Parses Queue(5)
            Fields: length(16), pad(16), queue_id(32), tx_bytes(64),
            tx_packets(64), tx_errors(64) = Bytes 32
        """

        count = len(packet[0:]) - 4
        queues = []
        while count > 0:
            flow_raw = packet[start:start+32]
            flow = unpack('!HHLQQQ', flow_raw)

            queue = OFP_STAT_QUEUE()
            queue.length = flow[0]
            queue.pad = flow[1]
            queue.queue_id = flow[2]
            queue.tx_bytes = flow[3]
            queue.tx_packets = flow[4]
            queue.tx_errors = flow[5]
            queues.append(queue)

            count = count - 32
            start = start + 32
            del queue

        msg.instantiate(queues)

    elif msg.stat_type == 65535:
        """
            Parse STAT_RES Vendor message
            Fields: vendor_id(32), data(?)
        """

        flow_raw = packet[start:start+4]
        flow = unpack('!L', flow_raw)
        vendor_id = flow[0]
        data = packet[start+4:]

        msg.instantiate(vendor_id, data)

    else:
        print ('StatRes: Unknown Type: %s' % (msg.stat_type))
    return 1


# ********************** BarrierReq ***********************
def parse_BarrierReq(msg, packet):
    pass


# ********************** BarrierRes ***********************
def parse_BarrierRes(msg, packet):
    pass


# ******************* QueueGetConfigReq *******************
def parse_QueueGetConfigReq(msg, packet):
    queue_raw = packet[0:4]
    queue = unpack('!HH', queue_raw)
    msg.port = queue[0]
    msg.pad = queue[1]


# ****************** QueueGetConfigRes ********************
def parse_QueueGetConfigRes(msg, packet):
    queue_raw = packet[0:8]
    queue = unpack('!H6s', queue_raw)
    msg.port = queue[0]
    msg.pad = queue[1]

    start = 8
    queues = []
    while (packet[start:] > 0):
        # Queues - it could be multiple
        # queue_id(32), length(16), pad(16)
        queue_raw = packet[start:start+8]
        queue = unpack('!LHH', queue_raw)

        equeue = OFP_QUEUE()
        equeue.queue_id = queue[0]
        equeue.length = queue[1]
        equeue.pad = queue[2]

        q_start = start + 8

        # Look of properties
        # property(16), length(16), pad(32), rate(16), pad(48)
        properties = packet[q_start:q_start+equeue.length-8]
        properties_list = []

        while (len(properties[q_start:]) > 0):
            prop_raw = packet[q_start:q_start+8]
            prop = unpack('!HHLH6s', prop_raw)

            property = OFP_QUEUE_PROPERTIES()
            property.property = prop[0]
            property.length = prop[1]
            property.pad = prop[2]
            property.payload = OFP_QUEUE_PROP_PAYLOAD()
            property.payload.rate = prop[3]
            property.payload.pad = prop[4]

            properties_list.append(property)
            del property

        equeue.properties = properties_list

        start = start + equeue.length

        queues.append(equeue)

    msg.queues = queues
