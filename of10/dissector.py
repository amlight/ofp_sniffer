"""
    This is the OpenFlow 1.0 dictionary/dissector
    Here messages, types and codes are converted to names.
"""


def get_ofp_type(of_type):
    of_types = {0: 'Hello',
                1: 'Error',
                2: 'EchoReq',
                3: 'EchoRes',
                4: 'Vendor',
                5: 'FeatureReq',
                6: 'FeatureRes',
                7: 'GetConfigReq',
                8: 'GetConfigRes',
                9: 'SetConfig',
                10: 'PacketIn',
                11: 'FlowRemoved',
                12: 'PortStatus',
                13: 'PacketOut',
                14: 'FlowMod',
                15: 'PortMod',
                16: 'StatsReq',
                17: 'StatsRes',
                18: 'BarrierReq',
                19: 'BarrierRes',
                20: 'QueueGetConfigReq',
                21: 'QueueGetConfigRes'}
    try:
        return of_types[of_type]
    except KeyError:
        return 'UnknownType(%s)' % of_type


def get_ofp_error(error_type, code):
    errors_types = dict()
    error_codes = dict()

    # Starts with an Error - exception
    errors_types[error_type] = 'UnknownType(%s)' % error_type
    error_codes[code] = 'UnknownCode(%s)' % code

    # Error Types
    if error_type in range(0, 6):
        errors_types = {0: 'HelloFailed(0)',
                        1: 'BadRequest(1)',
                        2: 'BadAction(2)',
                        3: 'FlowMod Failed(3)',
                        4: 'PortMod Failed(4)',
                        5: 'QueueOpFailed(5)'}

    # Error Codes per Error Type
    if error_type == 0:
        if error_codes in range(0, 2):
            error_codes = {0: 'Incompatible(0)',
                           1: 'EPerm(1)'}

    elif error_type == 1:
        if error_codes in range(0, 9):
            error_codes = {0: 'BadVersion(0)',
                           1: 'BadType(1)',
                           2: 'BadStat(2)',
                           3: 'BadVendor(3)',
                           4: 'BadSubtype(4)',
                           5: 'EPerm(5)',
                           6: 'BadLength(6)',
                           7: 'BufferEmpty(7)',
                           8: 'BufferUnknown(8)'}

    elif error_type == 2:
        if error_codes in range(0, 9):
            error_codes = {0: 'BadType',
                           1: 'BadLength',
                           2: 'BadVendor',
                           3: 'BadVendorType',
                           4: 'BadOutPort',
                           5: 'BadArgument',
                           6: 'EPerm',
                           7: 'TooMany',
                           8: 'BadQueue'}

    elif error_type == 3:
        if error_codes == 0 or error_codes in range(2, 7):
            error_codes = {0: 'AllTablesFull(0)',
                           2: 'Overlap(2)',
                           3: 'EPerm(3)',
                           4: 'BadEmergTimeout(4)',
                           5: 'BadCommand(5)',
                           6: 'Unsupported(6)'}

    elif error_type == 4:
        if error_codes in range(0, 2):
            error_codes = {0: 'BadPort(0)',
                           1: 'BadHwAddr(1)'}

    elif error_type == 5:
        if error_codes in range(0, 3):
            error_codes = {0: 'BadPort(0)',
                           1: 'BadQueue(1)',
                           2: 'EPerm(2)'}

    return errors_types[error_type], error_codes[code]


def get_ofp_vendor(vendor_id):
    # NICIRA / OVS: 0x2320 or 8992
    if vendor_id == 8992:
        return "NICIRA(%s)" % (hex(vendor_id))
    else:
        return str(vendor_id)


def get_ofp_command(command):
    commands = {0: 'Add(0)',
                1: 'Modify(1)',
                2: 'ModifyStrict(2)',
                3: 'Delete(3)',
                4: 'DeleteStrict(4)'}
    try:
        return commands[command]
    except KeyError:
        return 'UnknownCommand(%s)' % command


def get_vlan(vlan):
    vlans = {65535: 'Untagged(0xFFFF)'}
    try:
        return vlans[vlan]
    except KeyError:
        return vlan


def get_ofp_flags(flag):
    flags = {0: 'NoFlagSet(0)',
             1: 'SendFlowRem(1)',
             2: 'CheckOverLap(2)',
             3: 'Emerg(3)'}
    try:
        return flags[flag]
    except KeyError:
        return 'UnknownFlag(%s)' % flag


def get_flow_removed_reason(reason):
    rsn = {0: 'IdleTimeOut(0)',
           1: 'HardTimeOut(1)',
           2: 'Delete(2)'}
    try:
        return rsn[reason]
    except KeyError:
        return 'UnknownReason(%s)' % reason


def get_feature_res_capabilities(cap):
    caps = {1: 'FLOW_STATS(0x1)',
            2: 'TABLE_STATS(0x2)',
            4: 'PORT_STATS(0x4)',
            8: 'STP(0x8)',
            16: 'RESERVED(0x10)',
            32: 'IP_REASM(0x20)',
            64: 'QUEUE_STATS(0x40)',
            128: 'ARP_MATCH_IP(0x80)'}
    try:
        return caps[cap]
    except KeyError:
        return 'UnknownCapability(%s)' % cap


def get_feature_res_actions(action):
    actions = {1: 'OUTPUT(0x1)',
               2: 'SET_VLAN_VID(0x2)',
               4: 'SET_VLAN_PCP(0x4)',
               8: 'STRIP_VLAN(0x8)',
               16: 'SET_DL_SRC(0x10)',
               32: 'SET_DL_DST(0x20)',
               64: 'SET_NW_SRC(0x40)',
               128: 'SET_NW_DST(0x80)',
               256: 'SET_NW_TOS(0x100)',
               512: 'SET_TP_SRC(0x200)',
               1024: 'SET_TP_DST(0x400)',
               2048: 'ENQUEUE(0x800)'}
    try:
        return actions[action]
    except KeyError:
        return 'UnknownAction(%s)' % action


def get_phy_port_id(p_id):
    ids = {65280: 'Max(OxFF00)',
           65528: 'InPort(0xFFF8)',
           65529: 'Table(0xFFF9)',
           65530: 'Normal(0xFFFA)',
           65531: 'Flood(0xFFFB)',
           65532: 'All(0xFFFC)',
           65533: 'Controller(0xFFFD)',
           65534: 'Local(0xFFFE)',
           65535: 'None(0xFFFF)'}
    try:
        return ids[p_id]
    except KeyError:
        return '%s' % p_id


def get_phy_config(p_cfg):
    cfg = {1: 'PortDown(0x01)',
           2: 'NoSTP(0x02)',
           4: 'NoRecv(0x04)',
           8: 'NoRecvSTP(0x08)',
           16: 'NoFlood(0x10)',
           32: 'NoFwd(0x20)',
           64: 'NoPacketIn(0x40)'}
    try:
        return cfg[p_cfg]
    except KeyError:
        return 'UnknownConfig(%s)' % p_cfg


def get_phy_state(p_state):
    state = {0: 'STPListen(0x0)',
             1: 'LinkDown(0x1)',
             2: 'STPLearn(0x2)',
             4: 'STPForward(0x4)',
             8: 'STPBlock(0x8)',
             16: 'STPMask(0x10)'}
    try:
        return state[p_state]
    except KeyError:
        return 'UnknownState(%s)' % p_state


def get_phy_feature(p_feature):
    ftr = {1: '10MB_HD(0x1)',
           2: '10MB_FD(0x2)',
           4: '100MB_HD(0x4)',
           8: '100MB_FD(0x8)',
           16: '1GB_HD(0x10)',
           32: '1GB_FD(0x20)',
           64: '10GB_FD(0x40)',
           128: 'Copper(0x80)',
           256: 'Fiber(0x100)',
           512: 'AutoNeg(0x200)',
           1024: 'Pause(0x400)',
           2048: 'PauseAsym(0x800)'}
    try:
        return ftr[p_feature]
    except KeyError:
        return 'UnknownFeature(%s)' % p_feature


def get_configres_flags(flag):
    flags = {0: 'FRAG_NORMAL(0)',
             1: 'FRAG_DROP(1)',
             2: 'FRAG_REASM(2)',
             3: 'FRAG_MASK(3)'}
    try:
        return flags[flag]
    except KeyError:
        return 'UnknownFlag(%s)' % flag


def get_port_status_reason(reason):
    reasons = {0: 'OFPPR_ADD(0)',
               1: 'OFPPR_DELETE(1)',
               2: 'OFPPR_MODIFY(2)'}
    try:
        return reasons[reason]
    except KeyError:
        return 'UnknownReason(%s)' % reason


def get_packet_in_reason(reason):
    reasons = {0: 'OFPR_NO_MATCH(0)',
               1: 'OFPR_ACTION(1)'}
    try:
        return reasons[reason]
    except KeyError:
        return 'UnknownReason(%s)' % reason
