'''
    OpenFlow 1.3 Types and Codes
'''


def get_ofp_type(of_type):
    of_types = {0: 'Hello',
                1: 'Error',
                2: 'EchoReq',
                3: 'EchoRes',
                4: 'Experimenter',
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
                15: 'GroupMod',
                16: 'PortMod',
                17: 'TableMod',
                18: 'MultipartReq',
                19: 'MultipartRes',
                20: 'BarrierReq',
                21: 'BarrierRes',
                22: 'QueueGetConfigReq',
                23: 'QueueGetConfigRes',
                24: 'RoleReq',
                25: 'RoleRes',
                26: 'GetAsyncReq',
                27: 'GetAsyncRes',
                28: 'SetAsync',
                29: 'MeterMod'}
    try:
        return of_types[of_type]
    except:
        return 'UnknownType(%s)' % of_type


def get_ofp_error(error_type, code):
    errors_types = {}
    codes = {}

    # Starts with an Error
    errors_types[error_type] = 'UnknownType(%s)' % error_type
    codes[code] = 'UnknownCode(%s)' % code

    # Error Types
    if error_type in range(0, 14) or error_type == 65535:
        errors_types = {0: 'Hello_Failed(0)',
                        1: 'Bad_Request(1)',
                        2: 'Bad_Action(2)',
                        3: 'Bad_Instruction(3)',
                        4: 'Bad_Match(4)',
                        5: 'Flow_Mod_Failed(5)',
                        6: 'Group_Mod_Failed(6)',
                        7: 'Port_Mod_Failed(7)',
                        8: 'Table_Mod_Failed(8)',
                        9: 'Queue_Op_Failed(9)',
                        10: 'Switch_Config_Failed(10)',
                        11: 'Role_Request_Failed(11)',
                        12: 'Meter_Mod_Failed(12)',
                        13: 'Table_Features_Failed(13)',
                        65535: 'Experimenter(0xffff)'}

    # Error Codes per Error Type
    if error_type == 0:
        if code in range(0, 2):
            codes = {0: 'Incompatible(0)',
                     1: 'EPerm(1)'}

    elif error_type == 1:
        if code in range(0, 14):
            codes = {0: 'Bad_Version(0)',
                     1: 'Bad_Type(1)',
                     2: 'Multipart(2)',
                     3: 'Bad_Experimenter(3)',
                     4: 'Bad_Exp_Type(4)',
                     5: 'EPerm(5)',
                     6: 'Bad_Len(6)',
                     7: 'Buffer_Empty(7)',
                     8: 'Buffer_Unknown(8)',
                     9: 'Bad_Table_Id(9)',
                     10: 'Is_Slave(10)',
                     11: 'Bad_Port(11)',
                     12: 'Bad_Packet(12)',
                     13: 'Multipart_Buffer_Overflow(13)'}

    elif error_type == 2:
        if code in range(0, 16):
            codes = {0: 'Bad_Type(0)',
                     1: 'Bad_Len(1)',
                     2: 'Bad_Experimenter(2)',
                     3: 'Bad_Exp_Type(3)',
                     4: 'Bad_Out_Port(4)',
                     5: 'Bad_Argument(5)',
                     6: 'EPerm(6)',
                     7: 'Too_Many(7)',
                     8: 'Bad_Queue(8)',
                     9: 'Bad_Out_Group(9)',
                     10: 'Match_Inconsistent(10)',
                     11: 'Unsupported_Order(11)',
                     12: 'Bad_Tag(12)',
                     13: 'Bad_Set_Type(13)',
                     14: 'Bad_Set_Len(14)',
                     15: 'Bad_Set_Argument(15)'}

    elif error_type == 3:
        if code in range(0, 9):
            codes = {0: 'Unknown_Inst(0)',
                     1: 'Unsup_Inst(1)',
                     2: 'Bad_Table_Id(2)',
                     3: 'Unsup_Metadata(3)',
                     4: 'Unsup_Metadata_Mask(4)',
                     5: 'Bad_Experimenter(5)',
                     6: 'Bad_Exp_Type(6)',
                     7: 'Bad_Len(7)',
                     8: 'Eperm(8)'}

    elif error_type == 4:
        if code in range(0, 12):
            codes = {0: 'Bad_Type(0)',
                     1: 'Bad_Len(1)',
                     2: 'Bad_Tag(2)',
                     3: 'Bad_DL_Addr_Mask(3)',
                     4: 'Bad_NW_Addr_Mask(4)',
                     5: 'Bad_Wildcards(5)',
                     6: 'Bad_Field(6)',
                     7: 'Bad_Value(7)',
                     8: 'Bad_Mask(8)',
                     9: 'Bad_Prereq(9)',
                     10: 'Dup_Field(10)',
                     11: 'Eperm(11)'}

    elif error_type == 5:
        if code in range(0, 8):
            codes = {0: 'Unknown(0)',
                     1: 'Table_Full(1)',
                     2: 'Bad_Table_Id(2)',
                     3: 'Overlap(3)',
                     4: 'EPerm(4)',
                     5: 'Bad_Timeout(5)',
                     6: 'Bad_Command(6)',
                     7: 'Bad_Flags(7)'}

    elif error_type == 6:
        if code in range(0, 15):
            codes = {0: 'Group_Exists(0)',
                     1: 'Invalid_Group(1)',
                     2: 'Weight_Unsupported(2)',
                     3: 'Out_Of_Groups(3)',
                     4: 'Out_Of_Buckets(4)',
                     5: 'Chaining_Unsupported(5)',
                     6: 'Watch_Unsupported(6)',
                     7: 'Loop(7)',
                     8: 'Unknown_Group(8)',
                     9: 'Chained_Group(9)',
                     10: 'Bad_Type(10)',
                     11: 'Bad_Command(11)',
                     12: 'Bad_Bucket(12)',
                     13: 'Bad_Watch(13)',
                     14: 'Eperm(14)'}

    elif error_type == 7:
        if code in range(0, 5):
            codes = {0: 'Bad_Port(0)',
                     1: 'Bad_Hw_Addr(1)',
                     2: 'Bad_Config(2)',
                     3: 'Bad_Advertise(3)',
                     4: 'Eperm(4)'}

    elif error_type == 8:
        if code in range(0, 3):
            codes = {0: 'Bad_Table(0)',
                     1: 'Bad_Config(1)',
                     2: 'Eperm(2)'}

    elif error_type == 9:
        if code in range(0, 3):
            codes = {0: 'Bad_Port(0)',
                     1: 'Bad_Queue(1)',
                     2: 'Eperm(2)'}

    elif error_type == int('A', 16):
        if code in range(0, 3):
            codes = {0: 'Bad_Flags(0)',
                     1: 'Bad_Len(1)',
                     2: 'Eperm(2)'}

    elif error_type == int('B', 16):
        if code in range(0, 3):
            codes = {0: 'Stale(0)',
                     1: 'Unsupported(1)',
                     2: 'Bad_Role(2)'}

    elif error_type == int('C', 16):
        if code in range(0, 12):
            codes = {0: 'Unknown(0)',
                     1: 'Meter_Exists(1)',
                     2: 'Invalid_Meter(2)',
                     3: 'Unknown_Meter(3)',
                     4: 'Bad_Command(4)',
                     5: 'Bad_Flags(5)',
                     6: 'Bad_Rate(6)',
                     7: 'Bad_Burst(7)',
                     8: 'Bad_Band(8)',
                     9: 'Bad_Band_Value(9)',
                     10: 'Out_Of_Meters(10)',
                     11: 'Out_of_Bands(11)'}

    elif error_type == int('D', 16):
        if code in range(0, 6):
            codes = {0: 'Bad_Table(0)',
                     1: 'Bad_Metadata(1)',
                     2: 'Bad_Type(2)',
                     3: 'Bad_Length(3)',
                     4: 'Bad_Argument(4)',
                     5: 'Eperm(5)'}

    return errors_types[error_type], codes[code]


def get_feature_res_capabilities(cap):
    caps = {1: 'FLOW_STATS(0x1)',
            2: 'TABLE_STATS(0x2)',
            4: 'PORT_STATS(0x4)',
            8: 'GROUP_STATS(0x8)',
            32: 'IP_REASM(0x20)',
            64: 'QUEUE_STATS(0x40)',
            256: 'PORT_BLOCKED(0x100)'}
    try:
        return caps[cap]
    except:
        return 'UnknownCapability(%s)' % cap


def get_configres_flags(flag):
    flags = {0: 'FRAG_NORMAL(0)',
             1: 'FRAG_DROP(1)',
             2: 'FRAG_REASM(2)',
             3: 'FRAG_MASK(3)'}
    try:
        return flags[flag]
    except:
        return 'UnknownFlag(%s)' % flag


def get_phy_port_id(p_id):
    ids = {65280: 'Max(OxFF00)',
           65528: 'InPort(0xFFF8)',
           65529: 'Table(0xFFF9)',
           65530: 'Normal(0xFFFA)',
           65531: 'Flood(0xFFFB)',
           65532: 'All(0xFFFC)',
           65533: 'Controller(0xFFFD)',
           65534: 'Local(0xFFFE)',
           65535: 'Any(0xFFFF)'}
    try:
        return ids[p_id]
    except:
        return '%s' % p_id


def get_flow_match_fields(value):
    values = {0: 'In_Port',
              1: 'In_Phy_Port',
              2: 'Metadata',
              3: 'Eth_Dst',
              4: 'Eth_Src',
              5: 'Eth_Type',
              6: 'Vlan_VID',
              7: 'Vlan_PCP',
              8: 'IP_DSCP',
              9: 'IP_ECN',
              10: 'IP_PROTO',
              11: 'IPv4_Src',
              12: 'IPv4_Dst',
              13: 'TCP_Src',
              14: 'TCP_Dst',
              15: 'UDP_Src',
              16: 'UDP_Dst',
              17: 'SCTP_Src',
              18: 'SCTP_Dst',
              19: 'ICMPv4_Type',
              20: 'ICMPv4_Code',
              21: 'ARP_OP',
              22: 'ARP_SPA',
              23: 'ARP_TPA',
              24: 'ARP_SHA',
              25: 'ARP_THA',
              26: 'IPv6_Src',
              27: 'IPv6_Dst',
              28: 'IPv6_FLabel',
              29: 'ICMPv6_Type',
              30: 'ICMPv6_Code',
              31: 'IPv6_ND_Target',
              32: 'IPv6_ND_SLL',
              33: 'IPv6_ND_TLL',
              34: 'MPLS_Label',
              35: 'MPLS_TC',
              36: 'MPLS_BoS',
              37: 'PBB_ISID',
              38: 'Tunnel_ID',
              39: 'IPv6_EXTHDR'}

    try:
        return '%s(%s)' % (values[value], value)
    except:
        return 'UnknownMatchField(%s)' % value


def get_of_command(command):
    commands = {0: 'Add(0)',
                1: 'Modify(1)',
                2: 'ModifyStrict(2)',
                3: 'Delete(3)',
                4: 'DeleteStrict(4)'}
    try:
        return commands[command]
    except:
        return 'UnknownCommand(%s)' % command


def get_of_flags(flag):
    flags = {0: 'NoFlagSet(0)',
             1: 'SendFlowRem(0x1)',
             2: 'CheckOverLap(0x2)',
             4: 'ResetCounts(0x4)',
             16: 'NoPacketCounts(0x10)',
             32: 'NoByteCounts(0x20)'}
    try:
        return flags[flag]
    except:
        return 'UnknownFlag(%s)' % flag


def get_ipv6_extension(bit):
    options = {1: 'NO_NEXT',
               2: 'ESP',
               4: 'AUTH',
               8: 'DEST',
               16: 'FRAG',
               32: 'ROUTER',
               64: 'HOP',
               128: 'UNREP',
               256: 'UNSEQ'}
    try:
        return '%s(%s)' % (options[bit], hex(bit))
    except:
        return 'UnknownBit(%s)' % bit


def get_instructions(instruction):
    instructions = {1: 'GOTO_TABLE',
                    2: 'WRITE_METADATA',
                    3: 'WRITE_ACTIONS',
                    4: 'APPLY_ACTIONS',
                    5: 'CLEAR_ACTIONS',
                    6: 'METER',
                    65535: 'EXPERIMENTER'}

    try:
        return '%s(%s)' % (instructions[instruction], instruction)
    except:
        return 'UnknownInstruction(%s)' % instruction


