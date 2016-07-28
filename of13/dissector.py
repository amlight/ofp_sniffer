"""
    This is the OpenFlow 1.3 dictionary/dissector
    Here messages, types and codes are converted to names.
"""


def get_ofp_type(of_type):
    of_types = {0: 'OFPT_HELLO',
                1: 'OFPT_ERROR',
                2: 'OFPT_ECHO_REQUEST',
                3: 'OFPT_ECHO_REPLY',
                4: 'OFPT_EXPERIMENTER',
                5: 'OFPT_FEATURES_REQUEST',
                6: 'OFPT_FEATURES_REPLY',
                7: 'OFPT_GET_CONFIG_REQUEST',
                8: 'OFPT_GET_CONFIG_REPLY',
                9: 'OFPT_SET_CONFIG',
                10: 'OFPT_PACKET_IN',
                11: 'OFPT_FLOW_REMOVED',
                12: 'OFPT_PORT_STATUS',
                13: 'OFPT_PACKET_OUT',
                14: 'OFPT_FLOW_MOD',
                15: 'OFPT_GROUP_MOD',
                16: 'OFPT_PORT_MOD',
                17: 'OFPT_TABLE_MOD',
                18: 'OFPT_MULTIPART_REQUEST',
                19: 'OFPT_MULTIPART_REPLY',
                20: 'OFPT_BARRIER_REQUEST',
                21: 'OFPT_BARRIER_REPLY',
                22: 'OFPT_QUEUE_GET_CONFIG_REQUEST',
                23: 'OFPT_QUEUE_GET_CONFIG_REPLY',
                24: 'OFPT_ROLE_REQUEST',
                25: 'OFPT_ROLE_REPLY',
                26: 'OFPT_GET_ASYNC_REQUEST',
                27: 'OFPT_GET_ASYNC_REPLY',
                28: 'OFPT_SET_ASYNC',
                29: 'OFPT_METER_MOD'}
    try:
        return of_types[of_type]
    except KeyError:
        return 'UnknownType(%s)' % of_type


def get_ofp_error(error_type, code):
    errors_types = dict()
    codes = dict()

    # Starts with an Error
    errors_types[error_type] = 'UnknownType(%s)' % error_type
    codes[code] = 'UnknownCode(%s)' % code

    # Error Types
    if error_type in range(0, 14) or error_type == 65535:
        errors_types = {0: 'OFPET_HELLO_FAILED(0)',
                        1: 'OFPET_BAD_REQUEST(1)',
                        2: 'OFPET_BAD_ACTION(2)',
                        3: 'OFPET_BAD_INSTRUCTION(3)',
                        4: 'OFPET_BAD_MATCH(4)',
                        5: 'OFPET_FLOW_MOD_FAILED(5)',
                        6: 'OFPET_GROUP_MOD_FAILED(6)',
                        7: 'OFPET_PORT_MOD_FAILED(7)',
                        8: 'OFPET_TABLE_MOD_FAILED(8)',
                        9: 'OFPET_QUEUE_OP_FAILED(9)',
                        10: 'OFPET_SWITCH_CONFIG_FAILED(10)',
                        11: 'OFPET_ROLE_REQUEST_FAILED(11)',
                        12: 'OFPET_METER_MOD_FAILED(12)',
                        13: 'OFPET_TABLE_FEATURES_FAILED(13)',
                        65535: 'Experimenter(0xffff)'}

    # Error Codes per Error Type
    if error_type == 0:
        if code in range(0, 2):
            codes = {0: 'OFPHFC_INCOMPATIBLE(0)',
                     1: 'OFPHFC_EPERM(1)'}

    elif error_type == 1:
        if code in range(0, 14):
            codes = {0: 'OFPBRC_BAD_VERSION(0)',
                     1: 'OFPBRC_BAD_TYPE(1)',
                     2: 'OFPBRC_BAD_MULTIPART(2)',
                     3: 'OFPBRC_BAD_EXPERIMENTER(3)',
                     4: 'OFPBRC_BAD_EXP_TYPE(4)',
                     5: 'OFPBRC_EPERM(5)',
                     6: 'OFPBRC_BAD_LEN(6)',
                     7: 'OFPBRC_BUFFER_EMPTY(7)',
                     8: 'OFPBRC_BUFFER_UNKNOWN(8)',
                     9: 'OFPBRC_BAD_TABLE_ID(9)',
                     10: 'OFPBRC_IS_SLAVE(10)',
                     11: 'OFPBRC_BAD_PORT(11)',
                     12: 'OFPBRC_BAD_PACKET(12)',
                     13: 'OFPBRC_MULTIPART_BUFFER_OVERFLOW(13)'}

    elif error_type == 2:
        if code in range(0, 16):
            codes = {0: 'OFPBAC_BAD_TYPE(0)',
                     1: 'OFPBAC_BAD_LEN(1)',
                     2: 'OFPBAC_BAD_EXPERIMENTER(2)',
                     3: 'OFPBAC_BAD_EXP_TYPE(3)',
                     4: 'OFPBAC_BAD_OUT_PORT(4)',
                     5: 'OFPBAC_BAD_ARGUMENT(5)',
                     6: 'OFPBAC_EPERM(6)',
                     7: 'OFPBAC_TOO_MANY(7)',
                     8: 'OFPBAC_BAD_QUEUE(8)',
                     9: 'OFPBAC_BAD_OUT_GROUP(9)',
                     10: 'OFPBAC_MATCH_INCONSISTENT(10)',
                     11: 'OFPBAC_UNSUPPORTED_ORDER(11)',
                     12: 'OFPBAC_BAD_TAG(12)',
                     13: 'OFPBAC_BAD_SET_TYPE(13)',
                     14: 'OFPBAC_BAD_SET_LEN(14)',
                     15: 'OFPBAC_BAD_SET_ARGUMENT(15)'}

    elif error_type == 3:
        if code in range(0, 9):
            codes = {0: 'OFPBIC_UNKNOWN_INST(0)',
                     1: 'OFPBIC_UNSUP_INST(1)',
                     2: 'OFPBIC_BAD_TABLE_ID(2)',
                     3: 'OFPBIC_UNSUP_METADATA(3)',
                     4: 'OFPBIC_UNSUP_METADATA_MASK(4)',
                     5: 'OFPBIC_BAD_EXPERIMENTER(5)',
                     6: 'OFPBIC_BAD_EXP_TYPE(6)',
                     7: 'OFPBIC_BAD_LEN(7)',
                     8: 'OFPBIC_EPERM(8)'}

    elif error_type == 4:
        if code in range(0, 12):
            codes = {0: 'OFPBMC_BAD_TYPE(0)',
                     1: 'OFPBMC_BAD_LEN(1)',
                     2: 'OFPBMC_BAD_TAG(2)',
                     3: 'OFPBMC_BAD_DL_ADDR_MASK(3)',
                     4: 'OFPBMC_BAD_NW_ADDR_MASK(4)',
                     5: 'OFPBMC_BAD_WILDCARDS(5)',
                     6: 'OFPBMC_BAD_FIELD(6)',
                     7: 'OFPBMC_BAD_VALUE(7)',
                     8: 'OFPBMC_BAD_MASK(8)',
                     9: 'OFPBMC_BAD_PREREQ(9)',
                     10: 'OFPBMC_DUP_FIELD(10)',
                     11: 'OFPBMC_EPERM(11)'}

    elif error_type == 5:
        if code in range(0, 8):
            codes = {0: 'OFPFMFC_UNKNOWN(0)',
                     1: 'OFPFMFC_TABLE_FULL(1)',
                     2: 'OFPFMFC_BAD_TABLE_ID(2)',
                     3: 'OFPFMFC_OVERLAP(3)',
                     4: 'OFPFMFC_EPERM(4)',
                     5: 'OFPFMFC_BAD_TIMEOUT(5)',
                     6: 'OFPFMFC_BAD_COMMAND(6)',
                     7: 'OFPFMFC_BAD_FLAGS(7)'}

    elif error_type == 6:
        if code in range(0, 15):
            codes = {0: 'OFPGMFC_GROUP_EXISTS(0)',
                     1: 'OFPGMFC_INVALID_GROUP(1)',
                     2: 'OFPGMFC_WEIGHT_UNSUPPORTED(2)',
                     3: 'OFPGMFC_OUT_OF_GROUPS(3)',
                     4: 'OFPGMFC_OUT_OF_BUCKETS(4)',
                     5: 'OFPGMFC_CHAINING_UNSUPPORTED(5)',
                     6: 'OFPGMFC_WATCH_UNSUPPORTED(6)',
                     7: 'OFPGMFC_LOOP(7)',
                     8: 'OFPGMFC_UNKNOWN_GROUP(8)',
                     9: 'OFPGMFC_CHAINED_GROUP(9)',
                     10: 'OFPGMFC_BAD_TYPE(10)',
                     11: 'OFPGMFC_BAD_COMMAND(11)',
                     12: 'OFPGMFC_BAD_BUCKET(12)',
                     13: 'OFPGMFC_BAD_WATCH(13)',
                     14: 'OFPGMFC_EPERM(14)'}

    elif error_type == 7:
        if code in range(0, 5):
            codes = {0: 'OFPPMFC_BAD_PORT(0)',
                     1: 'OFPPMFC_BAD_HW_ADDR(1)',
                     2: 'OFPPMFC_BAD_CONFIG(2)',
                     3: 'OFPPMFC_BAD_ADVERTISE(3)',
                     4: 'OFPPMFC_EPERM(4)'}

    elif error_type == 8:
        if code in range(0, 3):
            codes = {0: 'OFPTMFC_BAD_TABLE(0)',
                     1: 'OFPTMFC_BAD_CONFIG(1)',
                     2: 'OFPTMFC_EPERM(2)'}

    elif error_type == 9:
        if code in range(0, 3):
            codes = {0: 'OFPQOFC_BAD_PORT(0)',
                     1: 'OFPQOFC_BAD_QUEUE(1)',
                     2: 'OFPQOFC_EPERM(2)'}

    elif error_type == int('A', 16):
        if code in range(0, 3):
            codes = {0: 'OFPSCFC_BAD_FLAGS(0)',
                     1: 'OFPSCFC_BAD_LEN(1)',
                     2: 'OFPSCFC_EPERM(2)'}

    elif error_type == int('B', 16):
        if code in range(0, 3):
            codes = {0: 'OFPRRFC_STALE(0)',
                     1: 'OFPRRFC_UNSUP(1)',
                     2: 'OFPRRFC_BAD_ROLE(2)'}

    elif error_type == int('C', 16):
        if code in range(0, 12):
            codes = {0: 'OFPMMFC_UNKNOWN(0)',
                     1: 'OFPMMFC_METER_EXISTS(1)',
                     2: 'OFPMMFC_INVALID_METER(2)',
                     3: 'OFPMMFC_UNKNOWN_METER(3)',
                     4: 'OFPMMFC_BAD_COMMAND(4)',
                     5: 'OFPMMFC_BAD_FLAGS(5)',
                     6: 'OFPMMFC_BAD_RATE(6)',
                     7: 'OFPMMFC_BAD_BURST(7)',
                     8: 'OFPMMFC_BAD_BAND(8)',
                     9: 'Bad_BOFPMMFC_BAD_BAND_VALUEand_Value(9)',
                     10: 'OFPMMFC_OUT_OF_METERS(10)',
                     11: 'OFPMMFC_OUT_OF_BANDS(11)'}

    elif error_type == int('D', 16):
        if code in range(0, 6):
            codes = {0: 'OFPTFFC_BAD_TABLE(0)',
                     1: 'OFPTFFC_BAD_METADATA(1)',
                     2: 'OFPTFFC_BAD_TYPE(2)',
                     3: 'OFPTFFC_BAD_LEN(3)',
                     4: 'OFPTFFC_BAD_ARGUMENT(4)',
                     5: 'OFPTFFC_EPERM(5)'}

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
    except KeyError:
        return 'UnknownCapability(%s)' % cap


def get_config_flags(flag):
    flags = {0: 'FRAG_NORMAL(0)',
             1: 'FRAG_DROP(1)',
             2: 'FRAG_REASM(2)',
             3: 'FRAG_MASK(3)'}
    try:
        return flags[flag]
    except KeyError:
        return 'UnknownFlag(%s)' % flag


def get_packet_in_reason(reason):
    reasons = {0: 'OFPR_NO_MATCH(0)',
               1: 'OFPR_ACTION(1)',
               2: 'OFPR_INVALID_TTL'}
    try:
        return reasons[reason]
    except KeyError:
        return 'UnknownReason(%s)' % reason


def get_flow_removed_reason(reason):
    rsn = {0: 'OFPRR_IDLE_TIMEOUT(0)',
           1: 'OFPRR_HARD_TIMEOUT(1)',
           2: 'OFPRR_DELETE(2)',
           3: 'OFPRR_GROUP_DELETE'}
    try:
        return rsn[reason]
    except KeyError:
        return 'UnknownReason(%s)' % reason


def get_port_status_reason(reason):
    reasons = {0: 'OFPPR_ADD(0)',
               1: 'OFPPR_DELETE(1)',
               2: 'OFPPR_MODIFY(2)'}
    try:
        return reasons[reason]
    except KeyError:
        return 'UnknownReason(%s)' % reason


def get_phy_port_id(p_id):
    ids = {4294967040: 'OFPP_MAX(OxFFFFFF00)',
           4294967288: 'OFPP_IN_PORT(0xFFFFFFF8)',
           4294967289: 'OFPP_TABLE(0xFFFFFFF9)',
           4294967290: 'OFPP_NORMAL(0xFFFFFFFA)',
           4294967291: 'OFPP_FLOOD(0xFFFFFFFB)',
           4294967292: 'OFPP_ALL(0xFFFFFFFC)',
           4294967293: 'OFPP_CONTROLLER(0xFFFFFFFD)',
           4294967294: 'OFPP_LOCAL(0xFFFFFFFE)',
           4294967295: 'OFPP_ANY(0xFFFFFFFF)'}
    try:
        return ids[p_id]
    except KeyError:
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
    except KeyError:
        return 'UnknownMatchField(%s)' % value


def get_flow_mod_command(command):
    commands = {0: 'OFPFC_ADD(0)',
                1: 'OFPFC_MODIFY(1)',
                2: 'OFPFC_MODIFY_STRICT(2)',
                3: 'OFPFC_DELETE(3)',
                4: 'OFPFC_DELETE_STRICT(4)'}
    try:
        return commands[command]
    except KeyError:
        return 'UnknownCommand(%s)' % command


def get_flow_mod_flags(flag):
    flags = {0: 'NoFlagSet(0)',
             1: 'OFPFF_SEND_FLOW_REM(0x1)',
             2: 'OFPFF_CHECK_OVERLAP(0x2)',
             4: 'OFPFF_RESET_COUNTS(0x4)',
             16: 'OFPFF_NO_PKT_COUNTS(0x10)',
             32: 'OFPFF_NO_BYT_COUNTS(0x20)'}
    try:
        return flags[flag]
    except KeyError:
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
    except KeyError:
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
    except KeyError:
        return 'UnknownInstruction(%s)' % instruction


def get_group_mod_command(command):
    commands = {0: 'OFPGC_ADD(0)',
                1: 'OFPGC_MODIFY(1)',
                2: 'OFPGC_DELETE(2)'}
    try:
        return commands[command]
    except KeyError:
        return 'UnknownCommand(%s)' % command


def get_group_mod_type(type):
    types = {0: 'OFPGT_ALL(0)',
             1: 'OFPGT_SELECT(1)',
             2: 'OFPGT_INDIRECT(2)',
             3: 'OFPGT_FF'}
    try:
        return types[type]
    except KeyError:
        return 'UnknownType(%s)' % type


def get_multipart_request_flags(flag):
    flags = {0: 'NOT_FLAG_SET(0)',
             1: 'OFPMPF_REQ_MORE(1)'}
    try:
        return flags[flag]
    except KeyError:
        return 'UnknownFlag(%s)' % flag


def get_multipart_reply_flags(flag):
    flags = {0: 'NOT_FLAG_SET(0)',
             1: 'OFPMPF_REPLY_MORE(1)'}
    try:
        return flags[flag]
    except KeyError:
        return 'UnknownFlag(%s)' % flag


def get_controller_role(role):
    roles = {0: 'OFPCR_ROLE_NOCHANGE(0)',
             1: 'OFPCR_ROLE_EQUAL(1)',
             2: 'OFPCR_ROLE_MASTER(2)',
             3: 'OFPCR_ROLE_SLAVE(3)'}
    try:
        return roles[role]
    except KeyError:
        return 'UnknownRole(%s)' % role