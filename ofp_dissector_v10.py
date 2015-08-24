from struct import unpack


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


def get_ofp_command(command):
    if command == 0:
        return 'Add'
    elif command == 1:
        return 'Modify'
    elif command == 2:
        return 'ModifyStrict'
    elif command == 3:
        return 'Delete'
    elif command == 4:
        return 'DeleteStrict'
    else:
        return 'MalFormed Packet'


def get_ofp_flags(flag):
    if flag == 1:
        return 'SendFlowRem'
    elif flag == 2:
        return 'CheckOverLap'
    elif flag == 3:
        return 'Emerg'
    else:
        return 'MalFormed Packet'


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


def get_flow_removed_reason(ofrem_reason):
    if ofrem_reason == 0:
        return 'IdleTimeOut'
    elif ofrem_reason == 1:
        return 'HardTimeOut'
    elif ofrem_reason == 2:
        return 'Delete'
    else:
        return 'PacketMalFormed'
