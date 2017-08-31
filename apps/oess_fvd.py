"""

"""

from datetime import datetime, timedelta
from libs.core.topo_reader import TopoReader


OFP_PACKET_IN = 10
OFP_PACKET_OUT = 13


class OessFvdTracer:

    def __init__(self):
        self.links = dict()
        self.starting()

    def starting(self):
        print('OESS FVD Monitoring')
        print('%-24s %s\t\t\t\t\t\t %s\t\t\t\t\t %s' %
              ('Link', 'Sent', 'Seen', 'Delay'))

    def process_packet(self, pkt):
        for msg in pkt.ofmsgs:
            if msg.ofp.header.message_type in [OFP_PACKET_IN, OFP_PACKET_OUT]:
                fvd = self._is_oess_fvd(msg.ofp.data)
                if fvd is not False:
                    # print(fvd.side_a, fvd.port_a, fvd.side_a,fvd.port_a, fvd.timestamp)
                    self.add_link(msg.ofp.header.message_type, fvd, pkt)

    def add_link(self, mtype, fvd, pkt):

        if fvd.side_a not in self.links:
            self.links[fvd.side_a] = dict()
        else:
            if fvd.port_a in self.links[fvd.side_a]:
                # If link was added to links before, ignore
                if mtype in [OFP_PACKET_OUT]:
                    return

        my_time = datetime.strptime(pkt.l1.time, '%Y-%m-%d %H:%M:%S')
        last_seen = 0 if mtype in [OFP_PACKET_OUT] else my_time

        self.links[fvd.side_a][fvd.port_a] = {'remote': fvd.side_z,
                                              'port': fvd.port_z,
                                              'timestamp': fvd.timestamp,
                                              'last_seen': last_seen}
        if mtype in [OFP_PACKET_IN]:
            self.print_link_status(fvd.side_a, fvd.port_a)

    def print_link_status(self, dpid, port):
        link = self.links[dpid][port]
        timestamp = str(datetime.fromtimestamp(link['timestamp']))

        diff = link['last_seen'] - datetime.fromtimestamp(link['timestamp'])
        if timedelta(seconds=14) > diff > timedelta(seconds=8):
            diff = str(diff) + '  <-- Attention!'
        elif diff > timedelta(seconds=14):
            diff = str(diff) + '  <-- Over 15 seconds!!'

        topo_link = TopoReader().get_link_aliases(dpid, port, link['remote'],
                                                  link['port'], option="Full")
        if len(topo_link) > 0:
            print('%-24s %s\t %s\t %s' %
                  (topo_link, timestamp, link['last_seen'], diff))
        else:
            print('%-24s %-4s %-24s %-4s %s\t\t\t\t\t %s\t\t\t\t\t %s' %
                  ('DPID', 'Port', 'Neighbor', 'Port', 'Sent', 'Seen', 'Delay'))
            print('%-24s %-4s %-24s %-4s %s\t %s\t %s' %
                  (dpid, port, link['remote'], link['port'], timestamp, link['last_seen'],
                   diff))

    def _is_oess_fvd(self, data):
        from libs.openflow.of10.process_data import dissect_data
        from pyof.foundation.basic_types import BinaryData

        if isinstance(data, BinaryData):
            data = dissect_data(data)

        try:
            next_protocol = '0x0000'
            eth = data.pop(0)
            next_protocol = eth.protocol

            if next_protocol in [33024]:
                vlan = data.pop(0)
                next_protocol = vlan.protocol

            if next_protocol in [34998]:
                fvd = data.pop(0)
                return fvd

            return False

        except Exception as error:
            print(error)
