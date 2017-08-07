"""

"""
from flask import Flask
import apps.ofp_stats


app = Flask(__name__)


class CreateRest(object):

    def __init__(self):
        self.run()

    @staticmethod
    @app.route("/members/<string:name>/")
    def get_member(name):
        return name

    # Production

    @staticmethod
    @app.route("/ofp_sniffer/start_time")
    def start_time():
        return apps.ofp_stats.OFStats().get_start_time()

    @staticmethod
    @app.route("/ofp_sniffer/packet_totals")
    def index():
        return apps.ofp_stats.OFStats().get_counter()

    @staticmethod
    @app.route("/ofp_sniffer/last_msgs")
    def last_msgs():
        return apps.ofp_stats.OFStats().get_last_msgs()

    @staticmethod
    def run():
        app.run(host='0.0.0.0')
