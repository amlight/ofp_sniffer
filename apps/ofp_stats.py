"""

"""
import json
import time
from _thread import start_new_thread as new_thread
from datetime import datetime

from apps.rest import CreateRest
from libs.singleton import Singleton


class CircularList(object):

    LIMIT = 500

    def __init__(self):
        self._queue = dict()
        self._num_items = 0

    @property
    def items(self):
        return self._queue

    def add(self, msg):
        """

        """

        if self._num_items < self.LIMIT - 1:
            self._queue[self._num_items] = msg.to_dict()
            self._num_items += 1
        elif self._num_items == self.LIMIT - 1:
            self._queue[self._num_items] = msg.to_dict()
            self._num_items = 0


class OFStats(metaclass=Singleton):

    def __init__(self):
        self.start_time = str(datetime.now())
        self.last_msgs = CircularList()
        self.num_packets = 0
        self.type_packets = self.init_type_packets()
        new_thread(self._run_rest, tuple())

    def init_type_packets(self):
        types = dict()
        types['1'] = dict()
        for of_type in range(0, 20):
            types['1'][str(of_type)] = 0
        types['4'] = dict()
        for of_type in range(0, 23):
            types['4'][str(of_type)] = 0
        return types

    @staticmethod
    def _run_rest():
        CreateRest()

    @staticmethod
    def to_json(msg):
        result = dict()
        result['result'] = msg
        return json.dumps(result)

    def get_unix_time(self):
        date = datetime.now()
        return time.mktime(date.timetuple())

    def get_time(self):
        return str(datetime.now())

    # REST Methods
    def get_start_time(self):
        """

        """
        msg = {'start_time': self.start_time}
        return self.to_json(msg)

    def get_counter(self):
        """

        """
        msg = dict()
        msg['current_time'] = self.get_time()
        msg['total_packets'] = self.num_packets
        msg['per_types'] = self.type_packets
        return self.to_json(msg)

    def get_last_msgs(self):
        """

        """
        return self.to_json(self.last_msgs.items)

    # Main Methods

    def compute_packet(self, pkt):
        self.num_packets += 1

        # self.last_msgs.add(of_msg.ofp)

        for of_msg in pkt.ofmsgs:
            # TODO: per DPID

            if of_msg.ofp.type == 16:
                self.last_msgs.add(of_msg.ofp)
            self.type_packets[str(of_msg.ofp.version)][str(of_msg.ofp.type)] += 1
