from datetime import datetime, timedelta


OFP_PACKET_IN = 10
OFP_PACKET_OUT = 13


class OessFvdTracer:

    def __init__(self):
        self.links = dict()
        self.starting()

    def starting(self):
        print('OESS FVD Monitoring')
        print('%-24s %-4s %-24s %-4s %s\t\t\t\t\t %s\t\t\t\t\t %s' %
              ('DPID', 'Port', 'Neighbor', 'Port', 'Last Seen', 'Timestamp', 'Delay'))

    def process_packet(self, pkt):
        for msg in pkt.ofmsgs:
            if msg.ofp.type in [OFP_PACKET_IN, OFP_PACKET_OUT]:
                fvd = self._is_oess_fvd(msg.ofp.data)
                if fvd is not False:
                    # print(fvd.side_a, fvd.port_a, fvd.side_a,fvd.port_a, fvd.timestamp)
                    self.add_link(msg.ofp.type, fvd)

    def add_link(self, mtype, fvd):

        if fvd.side_a not in self.links:
            self.links[fvd.side_a] = dict()
        else:
            if fvd.port_a in self.links[fvd.side_a]:
                # If link was added to links before, ignore
                if mtype in [OFP_PACKET_OUT]:
                    return

        last_seen = 0 if mtype in [OFP_PACKET_OUT] else datetime.now()
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


        print('%-24s %-4s %-24s %-4s %s\t %s\t %s' %
              (dpid, port, link['remote'], link['port'], link['last_seen'],
               timestamp, diff))

    def _is_oess_fvd(self, data):

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
