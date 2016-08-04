"""
    OpenFlow 1.3 message definition
"""


import prints as prints
import parser as parser


def instantiate(of_header):

    of_type = {0: ofp_hello, 1: ofp_error_msg, 2: ofp_echo_request, 3: ofp_echo_reply, 4: ofp_experimenter,
               5: ofp_switch_features_request, 6: ofp_switch_features_reply, 7: ofp_switch_config_request,
               8: ofp_switch_config, 9: ofp_switch_config, 10: ofp_packet_in, 11: ofp_flow_removed,
               12: ofp_port_status, 13: ofp_packet_out, 14: ofp_flow_mod, 15: ofp_group_mod, 16: ofp_port_mod,
               17: ofp_table_mod, 18: ofp_multipart_request, 19: ofp_multipart_reply, 20: ofp_barrier,
               21: ofp_barrier, 22: ofp_queue_get_config_request, 23: ofp_queue_get_config_reply, 24: ofp_role,
               25: ofp_role, 26: ofp_get_async_request, 27: ofp_async_config, 28: ofp_async_config, 29: ofp_meter_mod}

    try:
        return of_type[of_header['type']](of_header)
    except KeyError:
        return 0


# ################## OpenFlow Header ######################


class ofp_header:

    def __init__(self, of_header):
        self.version = 4
        self.type = of_header['type']
        self.length = of_header['length']
        self.xid = of_header['xid']


# ################## OFPT_HELLO ############################


class ofp_hello(ofp_header):

    class ofp_hello_elem_header:
        def __init__(self):
            self.type = None  # 2 bytes OFPHET_*
            self.length = None  # 2 bytes
            self.versionbitmap = []  # Length bytes, class ofp_hello_elem_versionbitmap

    class ofp_hello_elem_versionbitmap:

        def __init__(self):
            self.OFPHET_VERSIONBITMAP = 1
            self.type = self.OFPHET_VERSIONBITMAP  # 2 bytes
            self.length = None  # 2 bytes
            self.bitmaps = []  # 4 bytes array

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.elements = []  # Class ofp_hello_elem_header

    def process_msg(self, packet):
        parser.parse_hello(self, packet)

    def prints(self):
        prints.print_hello(self)


# ################## OFPT_ERROR ############################


class ofp_error_msg(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.error_type = None  # 2 bytes
        self.code = None  # 2 bytes
        self.data = []  # 1 Bytes x N

    def process_msg(self, packet):
        parser.parse_error_msg(self, packet)

    def prints(self):
        prints.print_error_msg(self)


# ################## OFPT_ECHO_REQUEST ############################


class ofp_echo_request(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.data = None  # Variable Length

    def process_msg(self, packet):
        parser.parse_echo_request(self, packet)

    def prints(self):
        prints.print_echo_request(self)


# ################## OFPT_ECHO_REPLY ############################


class ofp_echo_reply(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.data = None  # Variable Length

    def process_msg(self, packet):
        parser.parse_echo_reply(self, packet)

    def prints(self):
        prints.ofp_echo_reply(self)


# ################## OFPT_EXPERIMENTER ############################


class ofp_experimenter(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.experimenter = None  # 4 Bytes
        self.exp_type = None  # 4 Bytes

    def process_msg(self, packet):
        parser.parse_experimenter(self, packet)

    def prints(self):
        prints.print_experimenter(self)


# ################## OFPT_FEATURE_REQUEST ############################


class ofp_switch_features_request(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)

    def process_msg(self, packet):
        # ofp_switch_features_request has no body
        pass

    def prints(self):
        # ofp_switch_features_request has no body
        pass


# ################## OFPT_FEATURE_REQUEST ############################


class ofp_switch_features_reply(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.datapath_id = None  # 8 bytes
        self.n_buffers = None  # 4 bytes
        self.n_tbls = None  # 1 byte
        self.auxiliary_id = None  # 1 bytes
        self.pad = []  # 2 bytes
        self.capabilities = []  # 4 bytes
        self.reserved = None  # 4 bytes

    def process_msg(self, packet):
        parser.parse_switch_features(self, packet)

    def prints(self):
        prints.print_switch_features(self)


# ################## OFPT_GET_CONFIG_REQUEST ############################


class ofp_switch_config_request(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)

    def process_msg(self, packet):
        # ofp_switch_config_request has no body
        pass

    def prints(self):
        # ofp_switch_config_request has no body
        pass


# ########## OFPT_GET_CONFIG_REPLY & OFPT_SET_CONFIG ###############


class ofp_switch_config(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.flags = None
        self.miss_send_len = None

    def process_msg(self, packet):
        parser.parse_switch_config(self, packet)

    def prints(self):
        prints.print_switch_config(self)


# ################## OFPT_PACKET_IN ############################


class ofp_packet_in(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.buffer_id = None  # 4 bytes
        self.total_len = None  # 2 bytes
        self.reason = None  # 1 byte
        self.table_id = None  # 1 byte
        self.cookie = None  # 8 bytes
        self.match = ofp_match()  # auxiliary class ofp_match
        self.pad = None  # 2 bytes
        self.data = None  # 1 bytes x N

    def process_msg(self, packet):
        parser.parse_packet_in(self, packet)

    def prints(self):
        prints.print_packet_in(self)


# ################## OFPT_FLOW_REMOVED ############################


class ofp_flow_removed(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.cookie = None  # 8 bytes
        self.priority = None  # 2 bytes
        self.reason = None  # 1 byte
        self.table_id = None  # 1 byte
        self.duration_sec = None  # 4 bytes
        self.duration_nsec = None  # 4 bytes
        self.idle_timeout = None  # 2 bytes
        self.hard_timeout = None  # 2 bytes
        self.packet_count = None  # 8 bytes
        self.byte_count = None  # 8 bytes
        self.match = ofp_match()   # auxiliary class ofp_match()

    def process_msg(self, packet):
        parser.parse_flow_removed(self, packet)

    def prints(self):
        prints.print_flow_removed(self)


# ################## OFPT_PORT_STATUS ############################


class ofp_port_status(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.reason = None  # 8 bits
        self.pad = []  # 7 Bytes
        self.desc = ofp_port()  # ofp_port class

    def process_msg(self, packet):
        parser.parse_port_status(self, packet)

    def prints(self):
        prints.print_port_status(self)


# ################## OFPT_PACKET_OUT ############################


class ofp_packet_out(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.buffer_id = None  # 4 bytes
        self.in_port = None  # 4 bytes
        self.actions_len = None  # 2 bytes
        self.pad = None  # 6 bytes
        self.actions = []  # class ofp_action_header
        self.data = None  # 1 bytes x N - Ethernet packet

    def process_msg(self, packet):
        parser.parse_packet_out(self, packet)

    def prints(self):
        prints.print_packet_out(self)


# ################## OFPT_FLOW_MOD ############################


class ofp_flow_mod(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.cookie = None  # 8 bytes
        self.cookie_mask = None  # 8 bytes
        self.table_id = None  # 1 byte
        self.command = None  # 1 byte
        self.idle_timeout = None  # 2 bytes
        self.hard_timeout = None  # 2 bytes
        self.priority = None  # 2 bytes
        self.buffer_id = None  # 4 bytes
        self.out_port = None  # 4 bytes
        self.out_group = None  # 4 bytes
        self.flags = None  # 2 bytes
        self.pad = None  # 2 bytes
        self.match = ofp_match()  # Class ofp_match
        self.instructions = []  # Class ofp_instructions

    def process_msg(self, packet):
        parser.parse_flow_mod(self, packet)

    def prints(self):
        prints.print_flow_mod(self)


# ################## OFPT_GROUP_MOD ############################


class ofp_group_mod(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.command = None  # 2 bytes
        self.group_type = None  # 1 byte
        self.pad = None  # 1 byte
        self.group_id = None  # 4 bytes
        self.buckets = []  # class ofp_bucket

    def process_msg(self, packet):
        parser.parse_group_mod(self, packet)

    def prints(self):
        prints.print_group_mod(self)


# ################## OFPT_PORT_MOD ############################


class ofp_port_mod(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.port_no = None  # 4 bytes
        self.pad = None  # 4 Bytes
        self.hw_addr = None  # 6 bytes
        self.pad2 = None  # 2 Bytes
        self.config = None  # 4 bytes
        self.mask = None  # 4 bytes
        self.advertise = None  # 4 bytes - bitmap of OFPPF_*
        self.pad3 = None  # 4 Bytes

    def process_msg(self, packet):
        parser.parse_port_mod(self, packet)

    def prints(self):
        prints.print_port_mod(self)


# ################## OFPT_TABLE_MOD ############################


class ofp_table_mod(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.table_id = None  # 1 byte
        self.pad = None  # 3 bytes
        self.config = None  # 4 bytes - bitmap of OFPTC_*

    def process_msg(self, packet):
        parser.parse_table_mod(self, packet)

    def prints(self):
        prints.print_table_mod(self)


# ################## OFPT_MULTIPART_REQUEST ############################


class ofp_multipart_request(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.stat_type = None  # 2 bytes
        self.flags = None   # 2 bytes
        self.pad = None  # 4 bytes
        self.body = []  # content to be instantiated

    def instantiate(self, *args):
        if self.stat_type in [0, 3, 7, 8, 11, 13]:
            # These types have empty body. Here for documentation only
            pass
        elif self.stat_type == 1:
            self.body = ofp_flow_stats_request(*args)
        elif self.stat_type == 2:
            self.body = ofp_aggregate_stats_request(*args)
        elif self.stat_type == 4:
            self.body = ofp_port_stats_request(*args)
        elif self.stat_type == 5:
            self.body = ofp_queue_stats_request(*args)
        elif self.stat_type == 6:
            self.body = ofp_group_stats_request(*args)
        elif self.stat_type == 9:
            self.body = ofp_meter_multipart_requests(*args)
        elif self.stat_type == 10:
            self.body = ofp_meter_multipart_requests(*args)
        elif self.stat_type == 12:
            self.body = ofp_table_features(*args)
        elif self.stat_type == 65535:
            self.body = ofp_experimenter_multipart_header(*args)

    def process_msg(self, packet):
        parser.parse_multipart_request(self, packet)

    def prints(self):
        prints.print_multipart_request(self)


# ################## OFPT_MULTIPART_REPLY ############################


class ofp_multipart_reply(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.stat_type = None   # 2 bytes
        self.flags = None   # 2 bytes
        self.pad = None  # 4 bytes
        self.body = None  # content to be instantiated

    def instantiate(self, *args):
        if self.stat_type == 0:
            self.body = ofp_desc(*args)
        elif self.stat_type == 1:
            self.body = ofp_flow_stats(*args)
        elif self.stat_type == 2:
            self.body = ofp_aggregate_stats_reply(*args)
        elif self.stat_type == 3:
            self.body = ofp_table_stats(*args)
        elif self.stat_type == 4:
            self.body = ofp_port_stats(*args)
        elif self.stat_type == 5:
            self.body = ofp_queue_stats(*args)
        elif self.stat_type == 6:
            self.body = ofp_group_stats(*args)
        elif self.stat_type == 7:
            self.body = ofp_group_desc(*args)
        elif self.stat_type == 8:
            self.body = ofp_group_features(*args)
        elif self.stat_type == 9:
            self.body = ofp_meter_stats(*args)
        elif self.stat_type == 10:
            self.body = ofp_meter_config(*args)
        elif self.stat_type == 11:
            self.body = ofp_meter_features(*args)
        elif self.stat_type == 12:
            self.body = ofp_table_features(*args)
        elif self.stat_type == 13:
            self.body = ofp_port_stats(*args)
        elif self.stat_type == 65535:
            self.body = ofp_experimenter_multipart_header(*args)

    def process_msg(self, packet):
        parser.parse_multipart_reply(self, packet)

    def prints(self):
        prints.print_multipart_reply(self)


# ########## OFPT_BARRIER_REQUEST & OFPT_BARRIER_REPLY ############


class ofp_barrier(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)

    def process_msg(self, packet):
        # ofp_barrier has no body
        pass

    def prints(self):
        # ofp_barrier has no body
        pass


# ################## OFPT_QUEUE_GET_CONFIG_REQUEST ############################


class ofp_queue_get_config_request(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.port = None  # 4 bytes
        self.pad = []  # 4 bytes

    def process_msg(self, packet):
        parser.parse_queue_get_config_request(self, packet)

    def prints(self):
        prints.print_queue_get_config_request(self)


# ################## OFPT_QUEUE_GET_CONFIG_REPLY ############################


class ofp_queue_get_config_reply(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.port = None  # 4 bytes
        self.pad = []  # 4 Bytes
        self.queues = []  # Class ofp_packet_queue[]

    def process_msg(self, packet):
        parser.parse_queue_get_config_reply(self, packet)

    def prints(self):
        prints.print_queue_get_config_reply(self)


# ########## OFPT_ROLE_REQUEST & OFPT_ROLE_REPLY ###############


class ofp_role(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.role = None  # 8 bytes
        self.pad = None  # 4 bytes
        self.generation_id = None  # 8 bytes

    def process_msg(self, packet):
        parser.parse_role(self, packet)

    def prints(self):
        prints.print_role(self)


# ################## OFPT_GET_ASYNC_REQUEST ############################


class ofp_get_async_request(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)

    def process_msg(self, packet):
        pass

    def prints(self):
        pass


# ########### OFPT_GET_ASYNC_REPLY & OFPT_SET_ASYNC #####################


class ofp_async_config(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.packet_in_mask = None  # 2 x 32 bits
        self.port_status_mask = None  # 2 x 32 bits
        self.flow_removed_mask = None  # 2 x 32 bits

    def process_msg(self, packet):
        parser.parse_async_config(self, packet)

    def prints(self):
        prints.print_async_config(self)


# ################## OFPT_METER_MOD ############################


class ofp_meter_mod(ofp_header):

    def __init__(self, of_header):
        ofp_header.__init__(self, of_header)
        self.command = None  # 2 bytes
        self.flags = None  # 2 bytes
        self.meter_id = None  # 4 bytes
        self.bands = []  # class ofp_meter_band_header

    def process_msg(self, packet):
        parser.parse_meter_mod(self, packet)

    def prints(self):
        prints.print_meter_mod(self)


# ######### Auxiliary Data Structures #############


class ofp_port:

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
        self.type = None
        self.length = None
        self.oxm_fields = []  # ofp_match_oxm_fields
        self.pad = None


class ofp_match_oxm_fields:

    def __init__(self):
        self.oxm_class = None
        self.field = None
        self.hasmask = None
        self.length = None
        self.payload = ofp_match_oxm_payload()  # ofp_match_oxm


class ofp_match_oxm_payload:

    def __init__(self):
        self.value = None
        self.mask = None


class ofp_instruction:

    def __init__(self, i_type, length):
        self.type = i_type
        self.length = length


class ofp_instruction_go_to(ofp_instruction):

    def __init__(self, i_type, length):
        ofp_instruction.__init__(self, i_type, length)
        self.table_id = None
        self.pad = None


class ofp_instruction_write_metadata(ofp_instruction):

    def __init__(self, i_type, length):
        ofp_instruction.__init__(self, i_type, length)
        self.pad = None
        self.metadata = None
        self.metadata_mask = None


class ofp_instruction_wac_actions(ofp_instruction):

    def __init__(self, i_type, length):
        ofp_instruction.__init__(self, i_type, length)
        self.pad = None
        self.actions = []  # class ofp_action


class ofp_instruction_meter(ofp_instruction):

    def __init__(self, i_type, length):
        ofp_instruction.__init__(self, i_type, length)
        self.meter_id = None


class ofp_instruction_experimenter(ofp_instruction):

    def __init__(self, i_type, length):
        ofp_instruction.__init__(self, i_type, length)
        self.experimenter_id = None


class ofp_action:

    def __init__(self, a_type, a_length):
        self.type = a_type
        self.length = a_length
        self.pad = None


class ofp_action_set_output(ofp_action):

    def __init__(self, a_type, a_length):
        ofp_action.__init__(self, a_type, a_length)
        self.port = None
        self.max_len = None


class ofp_action_set_vlan_vid(ofp_action):
    def __init__(self, a_type, a_length):
        ofp_action.__init__(self, a_type, a_length)
        self.vlan_vid = None
        self.pad = None


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


class ofp_flow_stats_request:
    def __init__(self, *args):
        pass


class ofp_aggregate_stats_request:
    def __init__(self, *args):
        pass


class ofp_port_stats_request:
    def __init__(self, *args):
        pass


class ofp_queue_stats_request:
    def __init__(self, *args):
        pass


class ofp_group_stats_request:
    def __init__(self, *args):
        pass


class ofp_meter_multipart_requests:
    def __init__(self, *args):
        pass


class ofp_table_features:
    def __init__(self, *args):
        pass


class ofp_experimenter_multipart_header:
    def __init__(self, *args):
        pass


class ofp_desc:
    def __init__(self, *args):
        pass


class ofp_flow_stats:
    def __init__(self, *args):
        pass


class ofp_aggregate_stats_reply:
    def __init__(self, *args):
        pass


class ofp_table_stats:
    def __init__(self, *args):
        pass


class ofp_port_stats:
    def __init__(self, *args):
        pass


class ofp_queue_stats:
    def __init__(self, *args):
        pass


class ofp_group_stats:
    def __init__(self, *args):
        pass


class ofp_group_desc:
    def __init__(self, *args):
        pass


class ofp_group_features:
    def __init__(self, *args):
        pass


class ofp_meter_stats:
    def __init__(self, *args):
        pass


class ofp_meter_config:
    def __init__(self, *args):
        pass


class ofp_meter_features:
    def __init__(self, *args):
        pass


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
