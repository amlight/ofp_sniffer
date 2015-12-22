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
