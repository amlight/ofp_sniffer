"""
    Class to read the topology.json file in use at AmLight
"""


import json
from libs.core.singleton import Singleton


class TopoReader(metaclass=Singleton):

    def __init__(self):
        self._dpids = {}
        self._links = {}
        self._port_map = {}
        self._topology = None
        self.readfile()

    def add_datapath(self, switch):
        for dpid in switch["dpids"]:
            self._dpids[dpid] = switch["aliases"][0]

        for port in switch["ports"]:
            self._port_map[switch["aliases"][0], switch["ports"][port]["ofport_no"]] = switch["ports"][port]["alias"]

    def add_datapath_port(self, switch, port):
        pass

    def add_link(self, link):
        self._links[link["datapath_a"], link["port_a"],
                    link["datapath_z"], link["port_z"]] = link["aliases"]
        self._links[link["datapath_z"], link["port_z"],
                    link["datapath_a"], link["port_a"]] = link["aliases"]

    def get_datapath_name(self, dpid=None):
        try:
            if dpid.find(":"):
                dpid = dpid.replace(":", "")

            return self._dpids[dpid]
        except KeyError:
            return dpid

    def get_datapath_id(self, alias=None):
        pass

    def get_port_name(self, dpid=None, port_no=None):
        try:
            return self._port_map[dpid, port_no]
        except KeyError:
            return port_no

    def get_port_id(self, dpid=None, alias=None):
        pass

    def clear_dpid(self, dpid):
        return self.get_datapath_name(dpid)

    def get_link_aliases(self, dp_a, port_a, dp_z, port_z, option="Full"):

        dp_a = self.clear_dpid(dp_a)
        dp_z = self.clear_dpid(dp_z)

        port_a = self.get_port_name(dp_a, port_a)
        port_z = self.get_port_name(dp_z, port_z)

        try:
            if option == "First":
                return self._links[dp_a, port_a, dp_z, port_z][0]
            elif option == "Full":
                return self._links[dp_a, port_a, dp_z, port_z][1]
            else:
                return self._links[dp_a, port_a, dp_z, port_z]
        except KeyError:
            return {}

    def get_link_config(self, alias=None):
        try:
            for link in self._topology["links"]:

                if alias in self._topology["links"][link]["aliases"]:
                    link = self._topology["links"][link]
                    return (link["datapath_a"], link["port_a"],
                            link["datapath_z"], link["port_z"])
        except:
            return {}

    def get_topology(self):
        return self._topology

    def readfile(self, topo_file="./docs/topology.json"):
        """

        """
        try:
            with open(topo_file) as jfile:
                self._topology = json.loads(jfile.read())
        except Exception as error:
            print("Error %s Opening file %s" % (error, topo_file))
            return

        for switch in self._topology['switches']:
            self.add_datapath(self._topology['switches'][switch])

        for link in self._topology['links']:
            self.add_link(self._topology['links'][link])
