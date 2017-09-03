"""
    This code is used to associate IP address seen to a switch when
    network slicing is in place.
    If FlowSpace Firewall or FlowVisor is not used, this module
    is not useful.
"""


from libs.core.singleton import Singleton
from libs.tcpiplib.packet import LLDP
from libs.core.topo_reader import TopoReader
from pyof.foundation.basic_types import BinaryData
from libs.openflow.of10.process_data import dissect_data
from libs.core.debugging import debugclass


#
#
# D_ADDR = None
# DEST_PORT = None
# NET = {}
# dpid_dict = {}
#
#
# def load_names_file(device_names):
#     default = 'docs/devices_list.json'
#     pfile = default if device_names == 0 else device_names
#
#     try:
#         with open(pfile) as jfile:
#             json_content = json.loads(jfile.read())
#     except Exception as error:
#         print("Error %s Opening file %s" % (error, pfile))
#         return
#
#     global dpid_dict
#     dpid_dict = json_content
#
#
# def insert_ip_port(dest_ip, dest_port):
#     """
#         Once the TCP/IP packet is dissected and a OpenFlow message type 13
#            (PacketOut) is seen, save both destination IP and TCP port
#         Args:
#             dest_ip: destination IP address
#             dest_port: destination TCP port
#     """
#     global D_ADDR
#     global DEST_PORT
#     D_ADDR = dest_ip
#     DEST_PORT = dest_port
#
#
# def clean_dpid(lldp):
#     try:
#         dpid = lldp.c_id.split(':')[1]
#     except IndexError:
#         dpid = lldp.c_id
#     return dpid
#
#
# def datapath_id(a):
#     """
#         Convert OpenFlow Datapath ID to human format
#     """
#     string = "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x"
#     dpid = string % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]),
#                      ord(a[4]), ord(a[5]), ord(a[6]), ord(a[7]))
#     return dpid
#
#
# def save_dpid(lldp):
#     """
#         Get the DPID from the LLDP.c_id
#         Args:
#             lldp: LLDP class
#     """
#     global NET
#
#     ip = D_ADDR
#     port = DEST_PORT
#     if isinstance(lldp, LLDP):
#         dpid = clean_dpid(lldp)
#     else:
#         dpid = datapath_id(lldp)
#
#     sw_name = get_name_dpid(dpid)
#     NET[ip, port] = sw_name
#
#
# def get_name_dpid(dpid):
#     sw_name = dpid_dict.get(dpid)
#     if sw_name is not None:
#         return sw_name
#     return 'OFswitch'
#
#
# def get_ip_name(ip, port):
#     for i, j in NET.items():
#         if i == (ip, port):
#             return '%s(%s)' % (ip, j)
#     return ip


@debugclass
class OFProxy(metaclass=Singleton):
    """

    """
    def __init__(self):
        self.dpid_dict = dict()  # dpid to alias dict
        self.proxy_db = dict()  # [ip, port] to alias dict
        self.load_topology_dpids()

    def load_topology_dpids(self):
        """
            Gets all DPIDs and datapath names from the
            topology.
        """
        topo = TopoReader().get_topology()
        for switch in topo['switches']:
            for dpid in topo['switches'][switch]['dpids']:
                self.add_dpid(dpid, TopoReader().get_datapath_name(dpid))

    def add_dpid(self, dpid, name):
        """
            Add dpid found in the topology to a dict

            Args:
                dpid: datapath_id
                name: datapath name
        """
        self.dpid_dict[dpid] = name

    def get_datapath_name(self, dpid):
        """

        :param dpid:
        :return:
        """
        return self.dpid_dict[dpid]

    def add_dpid_to_proxy_db(self, ip, port, dpid):
        """

        :param ip:
        :param port:
        :param dpid:
        :return:
        """
        dpid = self.clean_dpid(dpid)
        self.proxy_db[ip, port] = self.get_datapath_name(dpid)

    def clean_dpid(self, dpid):
        """

        :param dpid:
        :return:
        """

        if len(dpid.split(":")) == 2:
            return dpid.split(":")[1]

        elif len(dpid.split(":")) > 2:
            return dpid.replace(":", "")
        return dpid

    def process_packet(self, pkt):
        """
            Go through all OFMessages in Pkt.
            IF FeaturesReply or PacketOut...
        :param pkt:
        :return:
        """
        for msg in pkt.ofmsgs:
            if msg.ofp.header.message_type.value == 6:
                ip = pkt.l3.s_addr
                port = pkt.l4.source_port
                self.add_dpid_to_proxy_db(ip, port, msg.ofp.datapath_id)

            elif msg.ofp.header.message_type.value == 13:
                ip = pkt.l3.d_addr
                port = pkt.l4.dest_port
                lldp = self._is_lldp(msg.ofp.data)
                if isinstance(lldp, LLDP):
                    self.add_dpid_to_proxy_db(ip, port, lldp.c_id)

    @staticmethod
    def _is_lldp(data):
        """
            Check if Data is LLDP
            Args:
                data: PacketOut data
            Returns:
                LLDP class if it is an LLDP payload
                False if it is not
        """

        if isinstance(data, BinaryData):
            data = dissect_data(data)

        try:
            eth = data.pop(0)
            next_protocol = eth.protocol

            if next_protocol in [33024]:
                vlan = data.pop(0)
                next_protocol = vlan.protocol

            if next_protocol in [35020]:
                return data.pop(0)

            return False

        except Exception as error:
            print(error)
            return False

    def get_name(self, ip, port):
        """

        :param ip:
        :param port:
        :return:
        """
        for ip_port, name in self.proxy_db.items():
            if ip_port == (ip, port):
                return '%s(%s)' % (ip, name)
        return ip