"""
    This app was created to specifically monitor the
    OESS-FVD communication. It could be used to generate alarms
    when a packetIn is received with current time sent by the FVD
    too high compared with the time when the packet was
    captured.
"""

from datetime import datetime, timedelta
from libs.core.debugging import debugclass
from libs.core.topo_reader import TopoReader
from libs.tcpiplib.process_data import get_protocol


OFP_PACKET_IN = 10
OFP_PACKET_OUT = 13


@debugclass
class OessFvdTracer:
    """
        OessFvdTracer is an app to evaluate the OESS FVD app.
    """

    WARN = 10
    CRITICAL = 30

    def __init__(self, options):
        self.links = dict()
        self.layout = '%-20s %-14s %-30s %-30s %s'
        self.starting()
        self.last_printed = None
        self.get_params(options)

    @staticmethod
    def starting():
        """
            Just print the app name
        """
        print('OESS Forwarding Verification Monitoring')

    def get_params(self, options):
        """
            Process params provided via CLI
        """
        self.WARN = int(options.split(":")[0])
        self.CRITICAL = int(options.split(":")[1])

    def process_packet(self, pkt):
        """
            Method called by ofp_sniffer to process the IP+OF packet
            We are only interested in Packet_Ins because these are
            messages coming from the switch, which means, the end of
            the OESS FV cycle:
                (OESS -> packetOut -> dpid -> packetIn -> OESS)

            Args:
                pkt: Packet class
        """
        for msg in pkt.ofmsgs:
            if msg.ofp.header.message_type in [OFP_PACKET_IN]:
                fvd = get_protocol(msg.ofp.data, oess=True)
                if fvd is not False:
                    self.add_link(fvd, pkt.l1.time)

    def add_link(self, fvd, capture_time):
        """
            Add detected OESS link to self.links dictionary

            Args:
                fvd: OESS class
                capture_time: time when the packet was capture
                    by ofp_sniffer
        """

        if fvd.side_a not in self.links:
            self.links[fvd.side_a] = dict()

        capture_time = datetime.strptime(capture_time, '%Y-%m-%d %H:%M:%S.%f')

        time_diff = self.calculate_time_diff(capture_time, fvd.timestamp)

        self.links[fvd.side_a][fvd.port_a] = {'remote': fvd.side_z,
                                              'port': fvd.port_z,
                                              'timestamp': fvd.timestamp,
                                              'last_seen': capture_time,
                                              'diff': time_diff}

        self.print_link_status(fvd.side_a, fvd.port_a)

    @staticmethod
    def calculate_time_diff(capture_time, oess_time):
        """
            Calculate the time difference between packet sent via PacketOut
            and the packet received via PacketIn.

            Args:
                capture_time: PacketIn time
                oess_time: PacketOut time
            Returns:
                difference
        """
        return capture_time - datetime.fromtimestamp(oess_time)

    def print_link_status(self, dpid, port, alert=False):
        """
            Now, just print the OESS link detected. The idea of this method
            is to generate alarms when time different from the moment packet
            is seen by ofp_sniffer with the time packet was sent is over
            many seconds.

            Args:
                dpid: source DPID in the OESS message
                port: source port in the OESS message
                alert: print only warning and critical
        """

        link = self.links[dpid][port]

        timestamp = str(datetime.fromtimestamp(link['timestamp']))
        topo_link = TopoReader().get_link_aliases(dpid, port, link['remote'],
                                                  link['port'], option="Full")
        source_dpid = TopoReader().get_datapath_name(dpid)

        if link['diff'] < timedelta(seconds=0):
            print("Time Difference is < 0. Adjust NTP of the OF controller")

        elif timedelta(seconds=self.CRITICAL) > link['diff'] >= timedelta(seconds=self.WARN):
            link['diff'] = str(link['diff']) + '  <-- Warning!'
            alert = True

        elif link['diff'] >= timedelta(seconds=self.CRITICAL):
            link['diff'] = str(link['diff']) + '  <-- Critical!'
            alert = True

        if alert:
            if len(topo_link) > 0:
                self.print_header(True)
                print(self.layout % (topo_link, source_dpid, timestamp,
                                     link['last_seen'], link['diff']))
            else:
                self.print_header()
                print('%-24s %-4s %-24s %-4s %s\t %s\t %s' %
                      (dpid, port, link['remote'], link['port'], timestamp,
                       link['last_seen'], link['diff']))

    def print_header(self, topo_link=False):
        """
            Print headers just once. In case it keeps changing (because link
            was not found in the topology.json), prints the header again.

            Args:
                topo_link: indicates if link was found in the topology.json
        """
        if topo_link and self.last_printed in [None, 'not_topo_link']:
            print(self.layout % ('Link', 'Source DPID', 'Sent by OESS-FVD',
                                 'Received by OFP_Sniffer', 'Delay'))
            self.last_printed = 'topo_link'
        elif not topo_link and self.last_printed in [None, 'topo_link']:
            print('%-24s %-4s %-24s %-4s %s\t\t\t\t\t %s\t\t\t\t\t\t %s' %
                  ('DPID', 'Port', 'Neighbor', 'Port', 'Sent', 'Seen', 'Delay'))
            self.last_printed = 'not_topo_link'
