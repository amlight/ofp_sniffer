from struct import unpack
import of13.prints
import netaddr


def process_ofp_type13(of_type, packet, h_size, of_xid, print_options,
                       sanitizer):
    if of_type == 0:
        result = parse_Hello(packet, h_size, of_xid)
    elif of_type == 1:
        result = parse_Error(packet, h_size, of_xid)
    elif of_type == 2:
        result = parse_EchoReq(packet, h_size, of_xid)
    elif of_type == 3:
        result = parse_EchoRes(packet, h_size, of_xid)
    elif of_type == 4:
        result = parse_Experimenter(packet, h_size, of_xid)
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
        result = parse_PacketIn(packet, h_size, of_xid, sanitizer)
    elif of_type == 11:
        result = parse_FlowRemoved(packet, h_size, of_xid)
    elif of_type == 12:
        result = parse_PortStatus(packet, h_size, of_xid)
    elif of_type == 13:
        result = parse_PacketOut(packet, h_size, of_xid, sanitizer,
                                 print_options)
    elif of_type == 14:
        result = parse_FlowMod(packet, h_size, of_xid, print_options)
    elif of_type == 15:
        result = parse_GroupMod(packet, h_size, of_xid)
    elif of_type == 16:
        result = parse_PortMod(packet, h_size, of_xid)
    elif of_type == 17:
        result = parse_TableMod(packet, h_size, of_xid)
    elif of_type == 18:
        result = parse_MultipartReq(packet, h_size, of_xid)
    elif of_type == 19:
        result = parse_MultipartRes(packet, h_size, of_xid)
    elif of_type == 20:
        result = parse_BarrierReq(packet, h_size, of_xid)
    elif of_type == 21:
        result = parse_BarrierRes(packet, h_size, of_xid)
    elif of_type == 22:
        result = parse_QueueGetConfigReq(packet, h_size, of_xid)
    elif of_type == 23:
        result = parse_QueueGetConfigRes(packet, h_size, of_xid)
    elif of_type == 24:
        result = parse_RoleReq(packet, h_size, of_xid)
    elif of_type == 25:
        result = parse_RoleRes(packet, h_size, of_xid)
    elif of_type == 26:
        result = parse_GetAsyncReq(packet, h_size, of_xid)
    elif of_type == 27:
        result = parse_GetAsyncRes(packet, h_size, of_xid)
    elif of_type == 28:
        result = parse_SetAsync(packet, h_size, of_xid)
    elif of_type == 29:
        result = parse_MeterMod(packet, h_size, of_xid)
    else:
        return 0
    return result


# *************** Hello *****************
def parse_Hello(packet, h_size, of_xid):

    def process_bitmap(of_xid, bitmap):
        of13.prints.print_hello_bitmap(of_xid, bitmap)

    start = h_size
    count = 0
    while len(packet[start:]) > 0:
        # Get element[]
        count += 1
        elem_raw = packet[start:start+4]
        el_type, el_length = unpack('!HH', elem_raw)
        of13.prints.print_hello_elememnts(of_xid, el_type, el_length, count)

        bitmaps = packet[start+4:start+el_length]
        start_bit = 0

        while len(bitmaps[start_bit:]) > 0:
            bitmap_raw = packet[start_bit:start_bit+4]
            bitmap = unpack('!L', bitmap_raw)
            process_bitmap(of_xid, bitmap[0])
            start_bit = start_bit + 4

        start = start + el_length

    return 1


# ************** Error *****************
def parse_Error(packet, h_size, of_xid):
    of_error = packet[h_size:h_size+4]
    ofe = unpack('!HH', of_error)
    ofe_type = ofe[0]
    ofe_code = ofe[1]

    nameCode, typeCode = of13.dissector.get_ofp_error(ofe_type, ofe_code)
    of13.prints.print_of_error(of_xid, nameCode, typeCode)
    return 1


# ************ EchoReq *****************
def parse_EchoReq(packet, h_size, of_xid):
    of13.prints.print_echoreq(of_xid)
    return 1


# ************ EchoRes *****************
def parse_EchoRes(packet, h_size, of_xid):
    of13.prints.print_echores(of_xid)
    return 1


def parse_Experimenter(packet, h_size, of_xid):
    return 0


def parse_FeatureReq(packet, h_size, of_xid):
    of13.prints.print_of_feature_req(of_xid)
    return 1


# ******************** FeatureRes *******************
def _parse_bitmask(bitmask, array):
    size = len(array)
    for i in range(0, size):
        mask = 2**i
        aux = bitmask & mask
        if aux == 0:
            array.remove(mask)
    return array


def _parse_capabilities(capabilities):
    caps = [1, 2, 4, 8, 16, 32, 64, 128, 256]
    return _parse_bitmask(capabilities, caps)


def parse_FeatureRes(packet, h_size, of_xid):
    of_fres = packet[h_size:h_size+24]
    ofrs = unpack('!8sLBBHLL', of_fres)
    caps = []
    caps = _parse_capabilities(ofrs[5])

    f_res = {'datapath_id': ofrs[0], 'n_buffers': ofrs[1], 'n_tbls': ofrs[2],
             'auxiliary_id': ofrs[3], 'pad': ofrs[4], 'caps': caps,
             'reserved': ofrs[6]}

    of13.prints.print_of_feature_res(of_xid, f_res)
    return 1


# ***************** GetConfigReq *********************
def parse_GetConfigReq(packet, h_size, of_xid):
    of13.prints.print_of_getconfig_req(of_xid)
    return 1


# ***************** GetConfigRes ********************
def _parse_SetGetConfig(packet, h_size):
    pkt_raw = packet[h_size:h_size+4]
    pkt_list = unpack('!HH', pkt_raw)
    flag = of13.dissector.get_configres_flags(pkt_list[0])
    miss_send_len = pkt_list[1]
    return flag, miss_send_len


def parse_GetConfigRes(packet, h_size, of_xid):
    flag, miss_send_len = _parse_SetGetConfig(packet, h_size)
    of13.prints.print_of_getConfigRes(of_xid, flag, miss_send_len)
    return 1


# ******************* SetConfig **********************
def parse_SetConfig(packet, h_size, of_xid):
    flag, miss_send_len = _parse_SetGetConfig(packet, h_size)
    of13.prints.print_of_setConfig(of_xid, flag, miss_send_len)
    return 1


def parse_PacketIn(packet, h_size, of_xid, sanitizer):
    return 0


def parse_FlowRemoved(packet, h_size, of_xid):
    return 0


def parse_PortStatus(packet, h_size, of_xid):
    return 0


def parse_PacketOut(packet, h_size, of_xid, sanitizer, print_options):
    return 0


# ********************* FlowMod ***************************
def parse_ipv6_extension_header(extensions):
    bits = [1, 2, 4, 8, 16, 32, 64, 128, 256]
    return _parse_bitmask(extensions, bits)


def unpack_oxm_content(content_length, oxm_content, oxm):
    if oxm['hasmask'] == 0:
        if content_length == 1:
            strg = '!B'
        elif content_length == 2:
            strg = '!H'
        elif content_length == 3:
            strg = '!3s'
        elif content_length == 4:
            strg = '!L'
        elif content_length == 6:
            strg = '!6s'
        elif content_length == 8:
            strg = '!Q'
        elif content_length == 16:
            net, host = unpack('!QQ', oxm_content)
            ipv6 = ((net << 64) | host)
            oxm['value'] = netaddr.IPAddress(ipv6)
            return oxm

        oxm['value'] = unpack(strg, oxm_content)[0]

    else:
        if content_length == 2:
            strg = '!BB'
        elif content_length == 4:
            strg = '!HH'
        elif content_length == 6:
            strg = '!3s3s'
        elif content_length == 8:
            strg = '!LL'
        elif content_length == 12:
            strg = '!6s6s'
        elif content_length == 16:
            strg = '!QQ'
        elif content_length == 32:
            net, host, net1, host1 = unpack('!QQQQ', oxm_content)
            host = (net << 64) | host
            subnet = (net1 << 64) | host1
            oxm['value'] = netaddr.IPAddress(host)
            oxm['mask'] = netaddr.IPAddress(subnet)
            return oxm

        oxm['value'], oxm['mask'] = unpack(strg, oxm_content)
    return oxm


def print_oxm(of_xid, oxm, content_length, x_content):
    oxm = unpack_oxm_content(content_length, x_content, oxm)

    of13.prints.print_match_generic(of_xid, oxm)
    of13.prints.print_match(oxm)


def print_padding(padding):
    for i in range(0, padding):
        print '\b0',
    print


def _parse_matches(of_xid, packet, start):
    matches_raw = packet[start:start+4]
    matches = unpack('!HH', matches_raw)
    m_type = matches[0]
    m_length = matches[1]

    of13.prints.print_match_type(of_xid, m_type, m_length)

    length_oxm = (m_length - 4)
    padding = (((m_length + 7)/8*8 - m_length))

    start = start + 4
    oxms = packet[start:start+length_oxm]
    start_2 = 0

    while len(oxms[start_2:]) > 0:
        oxm_raw = oxms[start_2:start_2+4]
        oxm = unpack('!L', oxm_raw)
        x_class = (oxm[0] >> 16)
        x_field = ((oxm[0] >> 9) & 0x7f)
        x_hasmask = ((oxm[0] >> 8) & 1)
        x_length = (oxm[0] & 0xff)
        oxm_tlv = {'class': x_class, 'field': x_field, 'hasmask': x_hasmask,
                   'length': x_length}

        oxm_content = oxms[start_2+4:start_2+4+x_length]
        print_oxm(of_xid, oxm_tlv, len(oxm_content), oxm_content)
        start_2 = start_2 + 4 + x_length

    print ('%s Flow Matches - Padding: ' % of_xid),
    print_padding(padding)

    # Return offset for Instructions
    return start + length_oxm + padding


def _parse_actions(of_xid, packet, length):
    print '%s Actions: ' % (of_xid)


def _inst_goto_table(packet, start, i_len):
    print


def _inst_write_metadata(packet, start, i_len):
    print


def _inst_write_actions(packet, start, i_len):
    print


def _inst_apply_actions(of_xid, packet, start, i_len):
    print 'APPLY_ACTIONS'

    apply_raw = packet[start:start+4]
    apply_padding = unpack('!L', apply_raw)
    print '%s Padding: %s' % (of_xid, apply_padding[0])
    _parse_actions(of_xid, packet[start+4:], i_len-8)


def _inst_clear_actions(packet, start, i_len):
    print


def _inst_meter(packet, start, i_len):
    print


def _inst_experimenter(packet, start, i_len):
    print


def _parse_instructions(of_xid, packet, instructions_start):

    start = instructions_start

    while len(packet[start:]) > 0:
        instructions_raw = packet[instructions_start:instructions_start+4]
        instructions = unpack('!HH', instructions_raw)
        i_type = instructions[0]
        i_len = instructions[1]
        start = start + 4

        print ('%s Instructions:' % of_xid),
        # Call proper instruction
        if i_type == 1:
            _inst_goto_table(packet, start, i_len)
        elif i_type == 2:
            _inst_write_metadata(packet, start, i_len)
        elif i_type == 3:
            _inst_write_actions(packet, start, i_len)
        elif i_type == 4:
            _inst_apply_actions(of_xid, packet, start, i_len)
        elif i_type == 5:
            _inst_clear_actions(packet, start, i_len)
        elif i_type == 6:
            _inst_meter(packet, start, i_len)
        elif i_type == 65535:
            _inst_experimenter(packet, start, i_len)

        start = start + i_len - 4


def parse_FlowMod(packet, h_size, of_xid, print_options):
    flow_mod_raw = packet[h_size:h_size+40]
    ofmod = unpack('!QQBBHHHLLLHH', flow_mod_raw)

    cookie = ofmod[0] if ofmod[0] > 0 else 0
    cookie = '0x' + format(cookie, '02x')
    cookie_mask = ofmod[1] if ofmod[1] > 0 else 0
    cookie_mask = '0x' + format(cookie_mask, '02x')
    buffer_id = '0x' + format(ofmod[7], '02x')
    port = 65535 if ofmod[8] > 65535 else ofmod[8]

    flow_mod = {'cookie': cookie, 'cookie_mask': cookie_mask,
                'table_id': ofmod[2], 'command': ofmod[3],
                'idle_timeout': ofmod[4], 'hard_timeout': ofmod[5],
                'priority': ofmod[6], 'buffer_id': buffer_id,
                'out_port': port, 'out_group': ofmod[9],
                'flags': ofmod[10], 'padding': ofmod[11]}

    of13.prints.print_flow_mod(of_xid, flow_mod)

    instructions_start = _parse_matches(of_xid, packet, h_size+40)

    _parse_instructions(of_xid, packet, instructions_start)

    return 1


def parse_GroupMod(packet, h_size, of_xid):
    return 0


def parse_PortMod(packet, h_size, of_xid):
    return 0


def parse_TableMod(packet, h_size, of_xid):
    return 0


def parse_MultipartReq(packet, h_size, of_xid):
    return 0


def parse_MultipartRes(packet, h_size, of_xid):
    return 0


def parse_BarrierReq(packet, h_size, of_xid):
    of13.prints.print_of_BarrierReq(of_xid)
    return 1


def parse_BarrierRes(packet, h_size, of_xid):
    of13.prints.print_of_BarrierReply(of_xid)
    return 1


def parse_QueueGetConfigReq(packet, h_size, of_xid):
    return 0


def parse_QueueGetConfigRes(packet, h_size, of_xid):
    return 0


def parse_RoleReq(packet, h_size, of_xid):
    return 0


def parse_RoleRes(packet, h_size, of_xid):
    return 0


def parse_GetAsyncReq(packet, h_size, of_xid):
    return 0


def parse_GetAsyncRes(packet, h_size, of_xid):
    return 0


def parse_SetAsync(packet, h_size, of_xid):
    return 0


def parse_MeterMod(packet, h_size, of_xid):
    return 0
