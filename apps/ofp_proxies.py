"""
    This code is used to associate IP address seen to a switch when
    network slicing is in place.
    If FlowSpace Firewall or FlowVisor is not used, this module
    is not useful.
"""


from libs.core.singleton import Singleton
from libs.core.debugging import debugclass
from libs.core.topo_reader import TopoReader
from libs.tcpiplib.packet import LLDP
from libs.tcpiplib.process_data import get_protocol
from libs.gen.dpid_handling import clear_dpid


@debugclass
class OFProxy(metaclass=Singleton):
    """
        This app is used to help identifying switches when openflow
        proxies are in the middle, such as flowvisor and fsfw. It is
        not possible to deactivate it.
    """
    def __init__(self):
        self.dpid_dict = dict()  # dpid to alias dict
        self.proxy_db = dict()  # [ip, port] to alias dict
        self.active = False
        self.load_topology_dpids()

    def load_topology_dpids(self):
        """
            Gets all DPIDs and datapath names from the
            topology.
        """
        topo = TopoReader().get_topology()

        try:
            for switch in topo['switches']:
                for dpid in topo['switches'][switch]['dpids']:
                    self.add_dpid(dpid, TopoReader().get_datapath_name(dpid))
            self.active = True
        except KeyError:
            pass


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
            Get the switch name using dpid

            Args:
                dpid: datapath_id
            Returns:
                name: datapath name
        """
        try:
            return self.dpid_dict[dpid]
        except:
            return 'DPID_' + str(dpid)

    def add_dpid_to_proxy_db(self, ip_addr, port, dpid):
        """
            Receives the IP, TCP port and DPID and save them to the
            proxy_db. IP and TCP port are the indexes.

            Args:
                ip_addr: IP address
                port: TCP port
                dpid: switch datapath id
        """
        dpid = clear_dpid(dpid)
        self.proxy_db[ip_addr, port] = self.get_datapath_name(dpid)

    def process_packet(self, pkt):
        """
            Go through all OFMessages in Pkt.
            IF FeaturesReply or PacketOut, get the DPID

            pkt: packet class
        """

        if not self.active:
            return

        for msg in pkt.ofmsgs:
            if msg.ofp.header.message_type.value == 6:
                ip_addr = pkt.l3.s_addr
                port = pkt.l4.source_port
                self.add_dpid_to_proxy_db(ip_addr, port, msg.ofp.datapath_id.value)

            elif msg.ofp.header.message_type.value == 13:
                ip_addr = pkt.l3.d_addr
                port = pkt.l4.dest_port
                lldp = get_protocol(msg.ofp.data, lldp=True)
                if isinstance(lldp, LLDP):
                    self.add_dpid_to_proxy_db(ip_addr, port, lldp.c_id)

    def get_name(self, ip_addr, port):
        """
            Method used by the tcpiplib printing to associate
            ip:port to a switch name

            Args:
                ip_addr: IP address
                port: TCP port
                dpid: switch datapath id
        """
        if not self.active:
            return ip_addr

        for ip_port, name in self.proxy_db.items():
            if ip_port == (ip_addr, port):
                return '%s(%s)' % (ip_addr, name)
        return ip_addr
