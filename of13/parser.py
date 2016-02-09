from struct import unpack
import of13.prints
import netaddr


def process_ofp_type13(pkt):
    if pkt.of_h['type'] == 0:
        result = parse_Hello(pkt)
    elif pkt.of_h['type'] == 1:
        result = parse_Error(pkt)
    elif pkt.of_h['type'] == 2:
        result = parse_EchoReq(pkt)
    elif pkt.of_h['type'] == 3:
        result = parse_EchoRes(pkt)
    elif pkt.of_h['type'] == 4:
        result = parse_Experimenter(pkt)
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
        result = parse_GroupMod(pkt)
    elif pkt.of_h['type'] == 16:
        result = parse_PortMod(pkt)
    elif pkt.of_h['type'] == 17:
        result = parse_TableMod(pkt)
    elif pkt.of_h['type'] == 18:
        result = parse_MultipartReq(pkt)
    elif pkt.of_h['type'] == 19:
        result = parse_MultipartRes(pkt)
    elif pkt.of_h['type'] == 20:
        result = parse_BarrierReq(pkt)
    elif pkt.of_h['type'] == 21:
        result = parse_BarrierRes(pkt)
    elif pkt.of_h['type'] == 22:
        result = parse_QueueGetConfigReq(pkt)
    elif pkt.of_h['type'] == 23:
        result = parse_QueueGetConfigRes(pkt)
    elif pkt.of_h['type'] == 24:
        result = parse_RoleReq(pkt)
    elif pkt.of_h['type'] == 25:
        result = parse_RoleRes(pkt)
    elif pkt.of_h['type'] == 26:
        result = parse_GetAsyncReq(pkt)
    elif pkt.of_h['type'] == 27:
        result = parse_GetAsyncRes(pkt)
    elif pkt.of_h['type'] == 28:
        result = parse_SetAsync(pkt)
    elif pkt.of_h['type'] == 29:
        result = parse_MeterMod(pkt)
    else:
        return 0
    return result


# *************** Hello *****************
def parse_Hello(pkt):

    start = 0
    count = 0
    while len(pkt.packet[start:]) > 0:
        # Get element[]
        count += 1
        elem_raw = pkt.packet[start:start+4]
        hello_raw = unpack('!HH', elem_raw)
        hello = {'type': hello_raw[0], 'length': hello_raw[1], 'count': count}
        pkt.prepare_printing('print_hello_elements', hello)

        bitmaps = pkt.packet[start+4:start+hello['length']]
        start_bit = 0

        bmps = []
        while len(bitmaps[start_bit:]) > 0:
            bitmap_raw = pkt.packet[start_bit:start_bit+4]
            bitmap = unpack('!L', bitmap_raw)
            bmps.append(bitmap[0])
            start_bit = start_bit + 4

        pkt.prepare_printing('print_hello_bitmap', bmps)

        start = start + hello['length']

    return 1


# ************** Error *****************
def parse_Error(pkt):
    of_error = pkt.packet[0:4]
    ofe = unpack('!HH', of_error)
    ofe_type = ofe[0]
    ofe_code = ofe[1]

    codes = {}
    codes['name'], codes['type'] = of13.dissector.get_ofp_error(ofe_type,
                                                                ofe_code)
    pkt.prepare_printing('print_of_error', codes)
    return 1


# ************ EchoReq *****************
def parse_EchoReq(pkt):
    pkt.prepare_printing('print_echoreq', None)
    return 1


# ************ EchoRes *****************
def parse_EchoRes(pkt):
    pkt.prepare_printing('print_echores', None)
    return 1


def parse_Experimenter(pkt):
    return 0


def parse_FeatureReq(pkt):
    pkt.prepare_printing('print_of_feature_req', None)
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


def parse_FeatureRes(pkt):
    of_fres = pkt.packet[0:24]
    ofrs = unpack('!8sLBBHLL', of_fres)
    caps = []
    caps = _parse_capabilities(ofrs[5])

    f_res = {'datapath_id': ofrs[0], 'n_buffers': ofrs[1], 'n_tbls': ofrs[2],
             'auxiliary_id': ofrs[3], 'pad': ofrs[4], 'caps': caps,
             'reserved': ofrs[6]}

    pkt.prepare_printing('print_of_feature_res', f_res)
    return 1


# ***************** GetConfigReq *********************
def parse_GetConfigReq(pkt):
    pkt.prepare_printing('print_of_getconfig_req', None)
    return 1


# ***************** GetConfigRes ********************
def _parse_SetGetConfig(packet, h_size):
    pkt_raw = packet[h_size:h_size+4]
    pkt_list = unpack('!HH', pkt_raw)
    flag = of13.dissector.get_configres_flags(pkt_list[0])
    miss_send_len = pkt_list[1]
    return flag, miss_send_len


def parse_GetConfigRes(pkt):
    configres = {}
    configres['flag'], configres['miss'] = _parse_SetGetConfig(pkt.packet, 0)
    pkt.prepare_printing('print_of_getConfigRes', configres)
    return 1


# ******************* SetConfig **********************
def parse_SetConfig(pkt):
    setconfig = {}
    setconfig['flag'], setconfig['miss'] = _parse_SetGetConfig(pkt.packet, 0)
    pkt.prepare_printing('print_of_setConfig', setconfig)
    return 1


def parse_PacketIn(pkt):
    return 0


def parse_FlowRemoved(pkt):
    return 0


def parse_PortStatus(pkt):
    return 0


def parse_PacketOut(pkt):
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


def prepare_oxm(pkt, oxm, x_content):
    content_length = len(x_content)
    oxm = unpack_oxm_content(content_length, x_content, oxm)
    return oxm


def _parse_matches(pkt, start):
    matches_raw = pkt.packet[start:start+4]
    matches = {}
    matches['type'], matches['length'] = unpack('!HH', matches_raw)

    pkt.prepare_printing('print_match_type', matches)

    length_oxm = (matches['length'] - 4)
    padding = (((matches['length'] + 7)/8*8 - matches['length']))

    start = start + 4
    oxms = pkt.packet[start:start+length_oxm]
    start_2 = 0

    oxm_array = []
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
        # insert print_oxm into an array for printing.
        oxm_processed = prepare_oxm(pkt, oxm_tlv, oxm_content)
        oxm_array.append(oxm_processed)
        start_2 = start_2 + 4 + x_length

    pkt.prepare_printing('print_match', oxm_array)

    pads = {'message': padding}
    pkt.prepare_printing('print_padding', pads)

    # Return offset for Instructions
    return start + length_oxm + padding


def _parse_actions(packet, length):
    return
    print 'Actions: '


def _inst_goto_table(packet, start, i_len):
    print


def _inst_write_metadata(packet, start, i_len):
    print


def _inst_write_actions(packet, start, i_len):
    print


def _inst_apply_actions(pkt, start, i_len):
    string = {'message': 'APPLY_ACTIONS'}
    pkt.prepare_printing('print_string', string)

    apply_raw = pkt.packet[start:start+4]
    apply_padding = unpack('!L', apply_raw)
    string = {'message': apply_padding[0]}
    pkt.prepare_printing('print_padding', string)
    _parse_actions(pkt.packet[start+4:], i_len-8)


def _inst_clear_actions(packet, start, i_len):
    print


def _inst_meter(packet, start, i_len):
    print


def _inst_experimenter(packet, start, i_len):
    print


def _parse_instructions(pkt, instructions_start):

    start = instructions_start

    while len(pkt.packet[start:]) > 0:
        instructions_raw = pkt.packet[instructions_start:instructions_start+4]
        instructions = unpack('!HH', instructions_raw)
        i_type = instructions[0]
        i_len = instructions[1]
        start = start + 4

        string = {'message': 'Instructions:'}
        pkt.prepare_printing('print_instruction', string)
        # Call proper instruction
        if i_type == 1:
            _inst_goto_table(pkt, start, i_len)
        elif i_type == 2:
            _inst_write_metadata(pkt, start, i_len)
        elif i_type == 3:
            _inst_write_actions(pkt, start, i_len)
        elif i_type == 4:
            _inst_apply_actions(pkt, start, i_len)
        elif i_type == 5:
            _inst_clear_actions(pkt, start, i_len)
        elif i_type == 6:
            _inst_meter(pkt, start, i_len)
        elif i_type == 65535:
            _inst_experimenter(pkt, start, i_len)

        start = start + i_len - 4


def parse_FlowMod(pkt):
    flow_mod_raw = pkt.packet[0:40]
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

    pkt.prepare_printing('print_flow_mod', flow_mod)

    instructions_start = _parse_matches(pkt, 40)

    _parse_instructions(pkt, instructions_start)

    return 1


def parse_GroupMod(pkt):
    return 0


def parse_PortMod(pkt):
    return 0


def parse_TableMod(pkt):
    return 0


def parse_MultipartReq(pkt):
    return 0


def parse_MultipartRes(pkt):
    return 0


def parse_BarrierReq(pkt):
    pkt.prepare_printing('print_of_BarrierReq', None)
    return 1


def parse_BarrierRes(pkt):
    pkt.prepare_printing('print_of_BarrierReply', None)
    return 1


def parse_QueueGetConfigReq(pkt):
    return 0


def parse_QueueGetConfigRes(pkt):
    return 0


def parse_RoleReq(pkt):
    return 0


def parse_RoleRes(pkt):
    return 0


def parse_GetAsyncReq(pkt):
    return 0


def parse_GetAsyncRes(pkt):
    return 0


def parse_SetAsync(pkt):
    return 0


def parse_MeterMod(pkt):
    return 0
