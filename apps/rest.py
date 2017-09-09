"""
    This app creates the REST interface to be used
    by all apps that want to.
"""
from flask import Flask
import apps.ofp_stats


app = Flask(__name__)


class CreateRest(object):

    def __init__(self):
        self.run()

    @staticmethod
    @app.route("/ofp_sniffer/ofp_stats/start_time")
    def start_time():
        return apps.ofp_stats.OFStats().get_start_time()

    @staticmethod
    @app.route("/ofp_sniffer/ofp_stats/packet_totals")
    def index():
        return apps.ofp_stats.OFStats().get_counter()

    @staticmethod
    @app.route("/ofp_sniffer/ofp_stats/packet_totals/<string:dpid>")
    def per_dev_packet_types(dpid):
        return apps.ofp_stats.OFStats().get_packet_types_dpid(dpid)

    @staticmethod
    @app.route("/ofp_sniffer/ofp_stats/counter_type/<string:dpid>/<string:mtype>")
    def per_dev_per_type_counter(dpid, mtype):
        return apps.ofp_stats.OFStats().get_counter_per_type(dpid, mtype)

    @staticmethod
    @app.route("/ofp_sniffer/ofp_stats/last_msgs")
    def last_msgs():
        return apps.ofp_stats.OFStats().get_last_msgs()

    @staticmethod
    def run():
        app.run(host='0.0.0.0')
