"""
    This app process all OF messages to create statistics
    export via REST. Main user is Zabbix and SDN-LG
"""


import json
import time
from _thread import start_new_thread as new_thread
from datetime import datetime
from apps.rest import CreateRest
from libs.core.singleton import Singleton


class OFStats(metaclass=Singleton):
    """
        This class processes the OF messages for statistics.
    """

    def __init__(self):
        self.start_time = str(datetime.now())
        self.last_msgs = CircularList()
        self.num_packets = 0
        self.type_packets = self.init_type_packets()
        new_thread(self._run_rest, tuple())

    @staticmethod
    def init_type_packets():
        """
            Initialize all dictionaries
        """
        types = dict()
        types['1'] = dict()
        types['4'] = dict()
        return types

    @staticmethod
    def _run_rest():
        """
            This app only exports data via REST.
            So, load up the REST interface
        """
        CreateRest()

    @staticmethod
    def to_json(msg):
        """
            Convert dictionaries to JSON to export
            via REST
            Args:
                msg: message to be converted
            Returns:
                json.dumps
        """
        result = dict()
        result['result'] = msg
        return json.dumps(result)

    @staticmethod
    def get_unix_time():
        """
            Returns datetime.now() in unixstamp format.
        """
        date = datetime.now()
        return time.mktime(date.timetuple())

    @staticmethod
    def get_time():
        """
            Returns datetime.now() in string format.
        """
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
        """
            Method called by ofp_sniffer.py to process the OF message
        """
        self.num_packets += 1

        for of_msg in pkt.ofmsgs:
            version = str(of_msg.ofp.header.version.value)
            message_type = str(of_msg.ofp.header.message_type)
            message_type = message_type.split('.')[1]
            try:
                self.type_packets[version][message_type] += 1
            except KeyError:
                self.type_packets[version][message_type] = 1

            self.last_msgs.add(of_msg.ofp)


class CircularList(object):
    """
        This class only creates a new type: a CircularList.
        The idea is to export the last LIMIT messages via REST.
    """
    LIMIT = 500

    def __init__(self):
        self._queue = dict()
        self._num_items = 0

    @property
    def items(self):
        """
            Return all items
        """
        return self._queue

    def add(self, msg):
        """
            Add an OF message to the CircularList
        """

        if self._num_items < self.LIMIT - 1:
            self._queue[self._num_items] = {'time': str(datetime.now()), 'type': msg.header.message_type}
            self._num_items += 1
        elif self._num_items == self.LIMIT - 1:
            self._queue[self._num_items] = msg
            self._num_items = 0
