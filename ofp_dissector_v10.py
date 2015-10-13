from struct import unpack


def get_ofp_version(version):
    of_version = {0: 'Experimental',
                  1: '1.0',
                  2: '1.1',
                  3: '1.2',
                  4: '1.3',
                  5: '1.4',
                  6: '1.5'}

    if version not in range(0, 6):
        return 'Unknown'

    return of_version[version]


def get_ofp_type(type):
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

    if type not in range(0, 21):
                return 'Other'

    return of_types[type]


def get_ofp_error(error_type, code):
    if error_type == 0:
        if code == 0:
            return 'HelloFailed', 'Incompatible'
        elif code == 1:
            return 'HelloFailed', 'EPerm'
        else:
            return 'HelloFailed', 'UnknownCode'
    elif error_type == 1:
        if code == 0:
            return 'BadRequest', 'BadVersion'
        elif code == 1:
            return 'BadRequest', 'BadType'
        elif code == 2:
            return 'BadRequest', 'BadStat'
        elif code == 3:
            return 'BadRequest', 'BadVendor'
        elif code == 4:
            return 'BadRequest', 'BadSubtype'
        elif code == 5:
            return 'BadRequest', 'EPerm'
        elif code == 6:
            return 'BadRequest', 'BadLength'
        elif code == 7:
            return 'BadRequest', 'BufferEmpty'
        elif code == 8:
            return 'BadRequest', 'BufferUnknown'
        else:
            return 'BadRequest', 'UnknownCode'
    elif error_type == 2:
        if code == 0:
            return 'Bad Action', 'BadType'
        elif code == 2:
            return 'Bad Action', 'BadLength'
        elif code == 3:
            return 'Bad Action', 'BadVendor'
        elif code == 4:
            return 'Bad Action', 'BadVendorType'
        elif code == 5:
            return 'Bad Action', 'BadOutPort'
        elif code == 6:
            return 'Bad Action', 'BadArgument'
        elif code == 7:
            return 'Bad Action', 'EPerm'
        elif code == 8:
            return 'Bad Action', 'TooMany'
        elif code == 9:
            return 'Bad Action', 'BadQueue'
        else:
            return 'Bad Action', 'UnknownCode'
    elif error_type == 3:
        if code == 0:
            return 'FlowMod Failed', 'AllTablesFull'
        elif code == 2:
            return 'FlowMod Failed', 'Overlap'
        elif code == 3:
            return 'FlowMod Failed', 'EPerm'
        elif code == 4:
            return 'FlowMod Failed', 'BadEmergTimeout'
        elif code == 5:
            return 'FlowMod Failed', 'BadCommand'
        elif code == 6:
            return 'FlowMod Failed', 'Unsupported'
        else:
            return 'FlowMod Failed', 'UnknownCode'
    elif error_type == 4:
        if code == 0:
            return 'PortMod Failed', 'BadPort'
        elif code == 1:
            return 'PortMod Failed', 'BadHwAddr'
        else:
            return 'PortMod Failed', 'UnknownCode'
    elif error_type == 5:
        if code == 0:
            return 'QueueOpFailed', 'BadPort'
        elif code == 1:
            return 'QueueOpFailed', 'BadQueue'
        elif code == 2:
            return 'QueueOpFailed', 'EPerm'
        else:
            return 'QueueOpFailed', 'UnknownCode(' + str(code) + ')'
    else:
        return (('UnknownType(' + str(error_type) + ')'),
                ('UnknownCode(' + str(code) + ')'))


def get_ofp_vendor(vendor_id):
    # NICIRA / OVS: 0x2320 or 8992
    if vendor_id == 8992:
        return 'NICIRA(' + hex(vendor_id) + ')'
    else:
        return str(vendor_id)


def get_ofp_command(command):
    if command == 0:
        return 'Add(0)'
    elif command == 1:
        return 'Modify(1)'
    elif command == 2:
        return 'ModifyStrict(2)'
    elif command == 3:
        return 'Delete(3)'
    elif command == 4:
        return 'DeleteStrict(4)'
    else:
        return 'Unknown Command(' + str(command) + ')'


def get_ofp_flags(flag):
    if flag == 1:
        return 'SendFlowRem(1)'
    elif flag == 2:
        return 'CheckOverLap(2)'
    elif flag == 3:
        return 'Emerg(3)'
    else:
        return 'Unknown Flag(' + str(flag) + ')'


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
        type_4 = unpack('6s6s', payload)
        return type_4[0], type_4[1]
    # 5 - SetDLDst
    elif action_type == 5:
        type_5 = unpack('6s6s', payload)
        return type_5[0], type_5[1]
    # 6 - SetNWSrc
    elif action_type == 6:
        type_6 = unpack('L', payload)
        return type_6[0]
    # 7 - SetNWDst
    elif action_type == 7:
        type_7 = unpack('L', payload)
        return type_7[0]
    # 8 - SetNWTos
    elif action_type == 8:
        type_8 = unpack('B3s', payload)
        return type_8[0], type_8[1]
    # 9 - SetTPSrc
    elif action_type == 9:
        type_9 = unpack('HH', payload)
        return type_9[0], type_9[1]
    # a - SetTPDst
    elif action_type == int('a', 16):
        type_a = unpack('HH', payload)
        return type_a[0], type_a[1]
    # b - Enqueue
    elif action_type == int('b', 16):
        type_b = unpack('H6sL', payload)
        return type_b[0], type_b[1], type_b[2]
    # ffff - Vendor
    elif action_type == int('ffff', 16):
        type_f = unpack('L', payload)
        return type_f[0]


def get_flow_removed_reason(reason):
    rsn = {0: 'IdleTimeOut(0)',
           1: 'HardTimeOut(1)',
           2: 'Delete(2)'}
    try:
        return rsn[reason]
    except:
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
    except:
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
    except:
        return 'UnknownAction(%s)'% action


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
    except:
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
    except:
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
    except:
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
    except:
        return 'UnknownFeature(%s)' % p_feature


def get_configres_flags(flag):
    flags = {0: 'FRAG_NORMAL(0)',
           1: 'FRAG_DROP(1)',
           2: 'FRAG_REASM(2)',
           3: 'FRAG_MASK(3)'}
    try:
        return flags[flag]
    except:
        return 'UnknownFlag(%s)' % flag


def get_portStatus_reason(reason):
    reasons = {0: 'OFPPR_ADD(0)',
               1: 'OFPPR_DELETE(1)',
               2: 'OFPPR_MODIFY(2)'}
    try:
        return reasons[reason]
    except:
        return 'UnknownReason(%s)' % reason
