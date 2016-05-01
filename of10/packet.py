import prints as prints
import parser as parser


def instantiate(pkt, of_header):
    if of_header['type'] == 0:
        return OFPT_HELLO(of_header)
    elif of_header['type'] == 1:
        return OFPT_ERROR(of_header)
    elif of_header['type'] == 2:
        return OFPT_ECHO_REQ(of_header)
    elif of_header['type'] == 3:
        return OFPT_ECHO_RES(of_header)
    elif of_header['type'] == 4:
        return OFPT_VENDOR(of_header)
    elif of_header['type'] == 5:
        return OFPT_FEATURE_REQ(of_header)
    elif of_header['type'] == 6:
        return OFPT_FEATURE_RES(of_header)
    elif of_header['type'] == 7:
        return OFPT_GET_CONFIG_REQ(of_header)
    elif of_header['type'] == 8:
        return OFPT_GET_CONFIG_RES(of_header)
    elif of_header['type'] == 9:
        return OFPT_SET_CONFIG(of_header)
    elif of_header['type'] == 10:
        return OFPT_PACKET_IN(of_header)
    elif of_header['type'] == 11:
        return OFPF_FLOW_REMOVED(of_header)
    elif of_header['type'] == 12:
        return OFPT_PORT_STATUS(of_header)
    elif of_header['type'] == 13:
        return OFPT_PACKET_OUT(of_header)
    elif of_header['type'] == 14:
        return OFPT_FLOW_MOD(of_header)
    elif of_header['type'] == 15:
        return OFPT_PORT_MOD(of_header)
    elif of_header['type'] == 16:
        return OFPT_STATS_REQ(of_header)
    elif of_header['type'] == 17:
        return OFPT_STATS_RES(of_header)
    elif of_header['type'] == 18:
        return OFPT_BARRIER_REQ(of_header)
    elif of_header['type'] == 19:
        return OFPT_BARRIER_RES(of_header)
    elif of_header['type'] == 20:
        return OFPT_QUEUE_GET_CONFIG_REQ(of_header)
    elif of_header['type'] == 21:
        return OFPT_QUEUE_GET_CONFIG_RES(of_header)
    else:
        return 0


class OFPHeader:

    def __init__(self, of_header):
        self.version = 1
        self.type = of_header['type']
        self.length = of_header['length']
        self.xid = of_header['xid']


class OFPT_HELLO(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.data = None

    def process_msg(self, packet):
        parser.parse_Hello(self, packet)

    def prints(self):
        prints.print_of_hello(self)


class OFPT_ERROR(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.type = None
        self.code = None

    def process_msg(self, packet):
        parser.parse_Error(self, packet)

    def prints(self):
        prints.print_of_error(self)


class OFPT_ECHO_REQ(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.data = None

    def process_msg(self, packet):
        parser.parse_EchoReq(self, packet)

    def prints(self):
        prints.print_of_echoreq(self)


class OFPT_ECHO_RES(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.data = None

    def process_msg(self, packet):
        parser.parse_EchoRes(self, packet)

    def prints(self):
        prints.print_of_echores(self)


class OFPT_VENDOR(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.vendor = None
        self.data = None

    def process_msg(self, packet):
        parser.parse_Vendor(self, packet)

    def prints(self):
        prints.print_of_vendor(self)


class OFPT_FEATURE_REQ(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)

    def process_msg(self, packet):
        parser.parse_FeatureReq(self, packet)

    def prints(self):
        prints.print_of_feature_req(self)


class OFPT_FEATURE_RES(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.datapath_id = None
        self.n_buffers = None
        self.n_tbls = None
        self.pad = []  # 0-3 Bytes
        self.capabilities = []
        self.actions = []
        self.ports = []  # array of class ofp_phy_port

    def process_msg(self, packet):
        parser.parse_FeatureRes(self, packet)

    def prints(self):
        prints.print_of_feature_res(self)


class OFPT_GET_CONFIG_REQ(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)

    def process_msg(self, packet):
        parser.parse_GetConfigReq(self, packet)

    def prints(self):
        prints.print_of_getconfig_req(self)


class OFPT_GET_CONFIG_RES(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.flags = None
        self.miss_send_len = None

    def process_msg(self, packet):
        parser.parse_GetConfigRes(self, packet)

    def prints(self):
        prints.print_ofp_getConfigRes(self)


class OFPT_SET_CONFIG(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.flags = None
        self.miss_send_len = None

    def process_msg(self, packet):
        parser.parse_SetConfig(self, packet)

    def prints(self):
        prints.print_ofp_setConfig(self)


class OFPT_PACKET_IN(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.buffer_id = None
        self.total_len = None
        self.in_port = None
        self.reason = None
        self.pad = None
        self.data = None

    def process_msg(self, packet):
        parser.parse_PacketIn(self, packet)

    def prints(self):
        prints.print_of_packetIn(self)


class OFPF_FLOW_REMOVED(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.match = OFP_Match()
        self.cookie = None
        self.priority = None
        self.reason = None
        self.pad = None
        self.duration_sec = None
        self.duration_nsec = None
        self.idle_timeout = None
        self.pad2 = None
        self.pad3 = None
        self.packet_count = None
        self.byte_count = None

    def process_msg(self, packet):
        parser.parse_FlowRemoved(self, packet)

    def prints(self):
        prints.print_ofp_flow_removed(self)


class OFPT_PORT_STATUS(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.reason = None
        self.pad = []  # 0 - 7 Bytes
        self.desc = OFP_Phy_port()

    def process_msg(self, packet):
        parser.parse_PortStatus(self, packet)

    def prints(self):
        prints.print_portStatus(self)


class OFPT_PACKET_OUT(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.buffer_id = None
        self.in_port = None
        self.actions_len = None
        self.actions = []
        self.data = None

    def process_msg(self, packet):
        parser.parse_PacketOut(self, packet)

    def prints(self):
        prints.print_of_packetOut(self)


class OFPT_FLOW_MOD(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.match = OFP_Match()
        self.cookie = None
        self.command = None
        self.idle_timeout = None
        self.hard_timeout = None
        self.priority = None
        self.buffer_id = None
        self.out_port = None
        self.flags = None
        self.actions = []  # Class ofp_action_header

    def process_msg(self, packet):
        parser.parse_FlowMod(self, packet)

    def prints(self):
        prints.print_of_FlowMod(self)


class OFPT_PORT_MOD(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.port_no = None
        self.hw_addr = None
        self.config = None
        self.mask = None
        self.advertise = None
        self.pad = None

    def process_msg(self, packet):
        parser.parse_PortMod(self, packet)

    def prints(self):
        prints.print_of_PortMod(self)


class OFPT_STATS_REQ(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.stat_type = None
        self.flags = None
        self.stats = None

    def instantiate(self, *args):
        if self.stat_type in [1,2]:
            self.stats = OFP_STATSREQ_FLOWAGG(*args)
        elif self.stat_type == 4:
            self.stats = OFP_STATREQ_PORT(*args)
        elif self.stat_type == 5:
            self.stats = OFP_STATREQ_QUEUE(*args)
        elif self.stat_type == 65535:
            self.stats = OFP_STATREQ_VENDOR(*args)

    def process_msg(self, packet):
        parser.parse_StatsReq(self, packet)

    def prints(self):
        prints.print_ofp_statReq(self)


class OFPT_STATS_RES(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.stat_type = None
        self.flags = None
        self.stats = None

    def instantiate(self, *args):
        if self.stat_type == 0:
            self.stats = OFP_STATSRES_DESC(*args)
        elif self.stat_type == 1:
            self.stats = OFP_STATSRES_FLOW(*args)
        elif self.stat_type == 2:
            self.stats = OFP_STATSRES_AGG(*args)
        elif self.stat_type == 3:
            self.stats = OFP_STATSRES_TABLE(*args)
        elif self.stat_type == 4:
            self.stats = OFP_STATRES_PORT(*args)
        elif self.stat_type == 5:
            self.stats = OFP_STATRES_QUEUE(*args)
        elif self.stat_type == 65535:
            self.stats = OFP_STATRES_VENDOR(*args)

    def process_msg(self, packet):
        parser.parse_StatsRes(self, packet)

    def prints(self):
        prints.print_ofp_statRes(self)


class OFPT_BARRIER_REQ(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)

    def process_msg(self, packet):
        parser.parse_BarrierReq(self, packet)

    def prints(self):
        pass


class OFPT_BARRIER_RES(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)

    def process_msg(self, packet):
        parser.parse_BarrierReq(self, packet)

    def prints(self):
        pass


class OFPT_QUEUE_GET_CONFIG_REQ(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.port = None
        self.pad = []  # 0 - 2 Bytes

    def process_msg(self, packet):
        parser.parse_QueueGetConfigReq(self, packet)

    def prints(self):
        prints.print_queueReq(self)


class OFPT_QUEUE_GET_CONFIG_RES(OFPHeader):

    def __init__(self, of_header):
        OFPHeader.__init__(self, of_header)
        self.port = None
        self.pad = []  # 0 - 6 Bytes
        self.queues = []  # Class OFP_QUEUE[]

    def process_msg(self, packet):
        parser.parse_QueueGetConfigRes(self, packet)

    def prints(self):
        prints.print_queueRes(self)


# Auxiliary Data Structures
class OFP_Phy_port:

    def __init__(self):
        self.port_id = None
        self.hw_addr = None
        self.config = None
        self.state = None
        self.curr = None
        self.advertised = None
        self.supported = None
        self.peer = None


class OFP_Match:

    def __init__(self):
        self.wildcards = None
        self.in_port = None
        self.dl_src = None
        self.dl_dst = None
        self.dl_vlan = None
        self.dl_vlan_pcp = None
        self.pad1 = None
        self.dl_type = None
        self.nw_tos = None
        self.nw_proto = None
        self.pad2 = None
        self.nw_src = None
        self.nw_dst = None
        self.tp_src = None
        self.tp_dst = None


class OFP_Action:

    def __init__(self):
        self.type = None
        self.length = None
        self.payload = None

# OFP_STATS_REQ Auxiliary Classes

class OFP_STATSREQ_FLOWAGG:

    def __init__(self, match, table_id, pad, out_port):
        self.match = match
        self.table_id = table_id
        self.pad = pad
        self.out_port = out_port


class OFP_STATREQ_PORT:

    def __init__(self, port_number, pad):
        self.port_number = port_number
        self.pad = pad


class OFP_STATREQ_QUEUE:

    def __init__(self, port_number, pad, queue_id):
        self.port_number = port_number
        self.pad = pad
        self.queue_id = queue_id


class OFP_STATREQ_VENDOR:

    def __init__(self, vendor_id):
        self.vendor_id = vendor_id


# OFP_STATS_RES Auxiliary Classes

class OFP_STATSRES_DESC:

    def __init__(self, mfr_desc, hw_desc, sw_desc, serial_num, dp_desc):
        self.mfr_desc = mfr_desc
        self.hw_desc = hw_desc
        self.sw_desc = sw_desc
        self.serial_num = serial_num
        self.dp_desc = dp_desc


class OFP_STATSRES_FLOW:

    def __init__(self, flows):
        self.flows = flows  # Class OFP_STAT_FLOW[]


class OFP_STATSRES_AGG:

    def __init__(self, packet_count, byte_count, flow_count, pad):
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.flow_count = flow_count
        self.pad = pad


class OFP_STATSRES_TABLE:

    def __init__(self, tables):
        self.tables = tables  # Class OFP_STAT_TABLE[]


class OFP_STATRES_PORT:

    def __init__(self, ports):
        self.ports = ports  # Class OFP_STAT_PORT[]


class OFP_STATRES_QUEUE:

    def __init__(self, queues):
        self.queues = queues  # Class OFP_STAT_QUEUE[]


class OFP_STATRES_VENDOR:

    def __init__(self, vendor_id, data):
        self.vendor_id = vendor_id
        self.data = data


class OFP_STAT_FLOW:

    def __init__(self):
        self.length = None
        self.table_id = None
        self.pad = None
        self.match = None
        self.duration_sec = None
        self.duration_nsec = None
        self.priority = None
        self.idle_timeout = None
        self.hard_timeout = None
        self.pad2 = None
        self.cookie = None
        self.packet_count = None
        self.byte_count = None
        self.actions = None


class OFP_STAT_PORT:

    def __init__(self):
        self.port_number = None
        self.pad = None
        self.rx_packets = None
        self.tx_packets = None
        self.rx_bytes = None
        self.tx_bytes = None
        self.rx_dropped = None
        self.tx_dropped = None
        self.rx_errors = None
        self.tx_errors = None
        self.rx_frame_err = None
        self.rx_over_err = None
        self.rx_crc_err = None
        self.collisions = None


class OFP_STAT_TABLE:

    def __init__(self):
        self.table_id = None
        self.pad = None
        self.name = None
        self.wildcards = None
        self.max_entries = None
        self.active_count = None
        self.lookup_count = None
        self.matched_count = None


class OFP_STAT_QUEUE:

    def __init__(self):
        self.length = None
        self.pad = None
        self.queue_id = None
        self.tx_bytes = None
        self.tx_packets = None
        self.tx_errors = None


class OFP_QUEUE:

    def __init__(self):
        self.queue_id = None
        self.length = None
        self.pad = None
        self.properties = None


class OFP_QUEUE_PROPERTIES:

    def __init__(self):
        self.property = None
        self.length = None
        self.pad = None
        self.payload = None


class OFP_QUEUE_PROP_PAYLOAD:

    def __init__(self):
        self.rate = None
        self.pad = None