import of10.prints as prints
import gen.prints


class OFPHeader:

    def __init__(self):
        self.version = 1
        self.oftype = None
        self.lenght = None
        self.xid = None

    def prints(self):
        gen.prints.print_openflow_header(self)


class OFPT_HELLO:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.data = None

    def prints(self):
        self.ofp_header.prints()
        prints.print_of_hello(self.data)


class OFPT_ERROR:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.ertype = None
        self.code = None

    def prints(self):
        self.ofp_header.prints()
        prints.print_of_error(self)


class OFPT_ECHO_REQ:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.data = None

    def prints(self):
        prints.print_echoreq(self)


class OFPT_ECHO_RES:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.data = None

    def prints(self):
        prints.print_echoreq(self)


class OFPT_VENDOR:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.vendor = None
        self.data = None


class OFPT_FEATURE_REQ:

    def __init__(self):
        self.ofp_header = OFPHeader()


class OFPT_FEATURE_RES:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.datapath_id = None
        self.n_buffers = None
        self.n_tbls = None
        self.pad = []  # 0-3 Bytes
        self.capabilities = None
        self.actions = None
        self.ports = []  # class ofp_phy_port


class OFPT_GET_CONFIG_REQ:

    def __init__(self):
        self.ofp_header = OFPHeader()


class OFPT_GET_CONFIG_RES:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.flags = None
        self.miss_send_len = None


class OFPT_SET_CONFIG:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.flags = None
        self.miss_send_len = None


class OFPT_PACKET_OUT:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.buffer_id = None
        self.in_port = None
        self.actions_len = None
        self.data = None


class OFPF_FLOW_REMOVED:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.match = None
        self.cookie = None
        self.priority = None
        self.reason = None
        self.pad = []  # 0 - 1 Bytes
        self.duration_sec = None
        self.duration_nsec = None
        self.idle_timeout = None
        self.pad2 = []  # 0 - 2 Bytes
        self.packet_count = None
        self.byte_count = None


class OFPT_PORT_STATUS:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.reason = None
        self.pad = []  # 0 - 7 Bytes
        self.desc = None  # Class ofp_phy_port


class OFPT_PACKET_IN:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.buffer_id = None
        self.total_len = None
        self.in_port = None
        self.reason = None
        self.pad = None
        self.data = None


class OFPT_FLOW_MOD:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.match = ofp_match()
        self.cookie = None
        self.command = None
        self.idle_timeout = None
        self.hard_timeout = None
        self.priority = None
        self.buffer_id = None
        self.out_port = None
        self.flags = None
        self.actions = []  # Class ofp_action_header


class OFPT_PORT_MOD:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.port_no = None
        self.hw_addr = None
        self.config = None
        self.mask = None
        self.advertise = None
        self.pad = None


class OFPT_STATS_REQ:

    def __init__(self):
        self.ofp_header = OFPHeader()


class OFPT_STATS_RES:

    def __init__(self):
        self.ofp_header = OFPHeader()


class OFPT_BARRIER_REQ:

    def __init__(self):
        self.ofp_header = OFPHeader()


class OFPT_BARRIER_RES:

    def __init__(self):
        self.ofp_header = OFPHeader()


class OFPT_QUEUE_GET_CONFIG_REQ:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.port = None
        self.pad = []  # 0 - 2 Bytes


class OFPT_QUEUE_GET_CONFIG_RES:

    def __init__(self):
        self.ofp_header = OFPHeader()
        self.port = None
        self.pad = []  # 0 - 6 Bytes
        self.queues = []  # Class ofp_packet_queue


# Auxiliary Data Structures
class ofp_phy_port:

    def __init__(self):
        self.port_id = None
        self.hw_addr = None
        self.config = None
        self.state = None
        self.curr = None
        self.advertised = None
        self.supported = None
        self.peer = None


class ofp_match:

    def __init__(self):
        self.wildcards = None
        self.in_port = None
        self.dl_src = None
        self.dl_dst = None
        self.dl_vlan = None
        self.dl_vlan_pcp = None
        self.pad1 = []  # 0 - 1 Bytes
        self.dl_type = None
        self.nw_tos = None
        self.nw_proto = None
        self.pad2 = []  # 0 - 2 Bytes
        self.nw_src = None
        self.nw_dst = None
        self.tp_src = None
        self.tp_dst = None
