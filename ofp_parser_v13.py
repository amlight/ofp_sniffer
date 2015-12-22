from struct import unpack
# import ofp_dissector_v13
import ofp_prints_v13
# import socket


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
        ofp_prints_v13.print_hello_bitmap(of_xid, bitmap)

    start = h_size
    count = 0
    while len(packet[start:]) > 0:
        # Get element[]
        count += 1
        elem_raw = packet[start:start+4]
        el_type, el_length = unpack('!HH', elem_raw)
        ofp_prints_v13.print_hello_elememnts(of_xid, el_type, el_length, count)

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
    # of_error = packet[h_size:h_size+4]
    # ofe = unpack('!HH', of_error)
    # ofe_type = ofe[0]
    # ofe_code = ofe[1]

    #  nameCode, typeCode = ofp_dissector_v10.get_ofp_error(ofe_type, ofe_code)
    #  ofp_prints_v10.print_of_error(of_xid, nameCode, typeCode)
    return 0


# ************ EchoReq *****************
def parse_EchoReq(packet, h_size, of_xid):
    # ofp_prints_v10.print_echoreq(of_xid)
    return 0


# ************ EchoRes *****************
def parse_EchoRes(packet, h_size, of_xid):
    # ofp_prints_v10.print_echores(of_xid)
    return 0


def parse_Experimenter(packet, h_size, of_xid):
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


def parse_PacketIn(packet, h_size, of_xid, sanitizer):
    return 0


def parse_FlowRemoved(packet, h_size, of_xid):
    return 0


def parse_PortStatus(packet, h_size, of_xid):
    return 0


def parse_PacketOut(packet, h_size, of_xid, sanitizer, print_options):
    return 0


def parse_FlowMod(packet, h_size, of_xid, print_options):
    return 0


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
    return 0


def parse_BarrierRes(packet, h_size, of_xid):
    return 0


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
