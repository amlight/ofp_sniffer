"""
    This app process all OF messages to create statistics
    export via REST. Main user is Zabbix and SDN-LG
"""


import json
from datetime import datetime
from _thread import start_new_thread as new_thread
from pyof.foundation.basic_types import BinaryData
from pyof.v0x01.common.header import Type as Type10
from pyof.v0x04.common.header import Type as Type13
from libs.core.singleton import Singleton
from apps.rest import CreateRest
from apps.ofp_proxies import OFProxy


class OFStats(metaclass=Singleton):
    """
        This class processes the OF messages for statistics.
    """

    def __init__(self):
        self.start_time = str(datetime.now())
        self.last_msgs = CircularList()
        self.per_dev_last_msgs = dict()
        self.num_packets = 0
        self.packet_types = self.init_type_packets()
        self.per_dev_packet_types = dict()
        self.num_reconnects = 0
        new_thread(self._run_rest, tuple())

    @staticmethod
    def init_type_packets(version=None):
        """
            Initialize all dictionaries
        """
        definitions = {'1': Type10, '4': Type13}
        types = dict()

        if version is None:
            for version in definitions:
                types[version] = dict()
        else:
            types[version] = dict()

        for version in types:
            for of_type in definitions[version]:
                types[version][of_type.name] = 0

        return types

    @staticmethod
    def _run_rest():
        """
            This app only exports data via REST.
            So, load up the REST interface
        """
        CreateRest()

    @staticmethod
    def to_json(msg, integer=False):
        """
            Convert dictionaries to JSON to export
            via REST
            Args:
                msg: message to be converted
                integer: if int result is desired
            Returns:
                json.dumps
        """
        if integer:
            return json.dumps(msg)

        result = dict()
        result['result'] = msg
        return json.dumps(result)

    # REST Methods
    def get_start_time(self):
        """
            Just return when the ofp_sniffer started
        """
        msg = {'start_time': self.start_time}
        return self.to_json(msg)

    def get_counter(self):
        """
            Get counters via REST
        """
        msg = dict()
        msg['total'] = self.num_packets
        msg['per_types'] = self.packet_types
        msg['tcp_reconnects'] = self.num_reconnects
        return self.to_json(msg)

    def get_last_msgs(self):
        """
            Get the last messages seen
        """
        return self.to_json(self.last_msgs.items)

    def get_per_dev_last_msgs(self, dpid):
        """
            Get the last messages seen for dpid

            Args:
                dpid to be searched
        """
        if dpid in self.per_dev_last_msgs:
            return self.to_json(self.per_dev_last_msgs[dpid].items)
        else:
            return self.to_json({"error": "dpid %s not found" % dpid})

    def get_packet_types_dpid(self, dpid):
        """
            Get counters per dpid

            Args:
                dpid to be searched
        """
        if dpid in self.per_dev_packet_types:
            return self.to_json(self.per_dev_packet_types[dpid])
        else:
            return self.to_json({"error": "dpid %s not found" % dpid})

    def get_counter_per_type(self, dpid, mtype):
        """
            Get counters per dpid per type

            Args:
                dpid to be searched
                mtype to be searched
            Returns:
                the number of packets accounted
        """
        if dpid in self.per_dev_packet_types:
            for version in self.per_dev_packet_types[dpid]:
                return self.to_json(
                    self.per_dev_packet_types[dpid][version][mtype],
                    integer=True
                )
        else:
            return self.to_json({"error": "dpid %s not found" % dpid})

    # Processing methods
    def save_last_msgs_per_dev(self, pkt, ofp):
        """
            Creates per last messages queue per datapath

            Args:
                pkt: Packet class
                ofp: OFMessage.ofp attribute (OpenFlow message)
        """
        dpid = OFProxy().get_dpid(pkt.l3.s_addr, pkt.l4.source_port)

        if isinstance(dpid, bool):
            dpid = OFProxy().get_dpid(pkt.l3.d_addr, pkt.l4.dest_port)
            if isinstance(dpid, bool):
                return

        if dpid not in self.per_dev_last_msgs:
            self.per_dev_last_msgs[dpid] = CircularList()

        self.per_dev_last_msgs[dpid].add(pkt.l1.time, ofp)

    def process_per_dev_packet_types(self, pkt, ofp):
        """
            Creates counter per dpid

            Args:
                pkt: Packet class
                ofp: OFMessage.ofp attribute (OpenFlow message)
        """
        dpid = OFProxy().get_dpid(pkt.l3.s_addr, pkt.l4.source_port)

        if isinstance(dpid, bool):
            dpid = OFProxy().get_dpid(pkt.l3.d_addr, pkt.l4.dest_port)
            if isinstance(dpid, bool):
                return

        version = str(ofp.header.version.value)
        if dpid not in self.per_dev_packet_types:
            self.per_dev_packet_types[dpid] = self.init_type_packets(version)
            self.per_dev_packet_types[dpid]['total'] = 0

        message_type = str(ofp.header.message_type)
        message_type = message_type.split('.')[1]
        try:
            self.per_dev_packet_types[dpid][version][message_type] += 1
        except KeyError:
            self.per_dev_packet_types[dpid][version][message_type] = 1
        self.per_dev_packet_types[dpid]['total'] += 1

    # Main Method
    def process_packet(self, pkt):
        """
            Method called by ofp_sniffer.py to process the OF message
        """
        if pkt.reconnect_error:
            self.num_reconnects += 1
            return

        self.num_packets += 1

        for of_msg in pkt.ofmsgs:
            # Supporting /ofp_stats/packet_totals
            version = str(of_msg.ofp.header.version.value)
            message_type = str(of_msg.ofp.header.message_type)
            message_type = message_type.split('.')[1]
            try:
                self.packet_types[version][message_type] += 1
            except KeyError:
                self.packet_types[version][message_type] = 1

            # Supporting /ofp_stats/last_msgs
            self.last_msgs.add(pkt.l1.time, of_msg.ofp)

            # Supporting /ofp_stats/last_msgs/<DPID>
            self.save_last_msgs_per_dev(pkt, of_msg.ofp)

            # Support /ofp_stats/packet_totals/<string:dpid>
            self.process_per_dev_packet_types(pkt, of_msg.ofp)


class CircularList(object):
    """
        This class only creates a new type: a CircularList.
        The idea is to export the last LIMIT messages via REST.
    """
    LIMIT = 1000

    def __init__(self):
        self._queue = list()

    @property
    def items(self):
        """
            Return all items
        """
        return self._queue

    def add(self, timestamp, msg):
        """
            Add an OF message to the CircularList
        """
        if len(self._queue) == self.LIMIT:
            self._queue.pop(0)

        self._queue.append({'time': str(timestamp), 'msg': convert_class(msg)})

    def __len__(self):
        """
            Return number of elements on the queue
        """
        return len(self._queue)


def convert_class(cls):
    """
        This function is used to convert a python-openflow message
        to a dictionary that can be serialized later. This is used
        to send data via REST.

        This funcion works in a recursive way. So far, each
        python-openflow message can have three main types:

        value: it is a class that has an attribute "value" meaning
            it is 'terminal'
        list: it is a list of classes
        class: it is another class but it does not have a value

        For value, it returns the attribute
        For list, it circulates the list, going through each class,
            returning a list of classes
        For class, it uses vars to identify all attributes and calls
            the convert_class in a recursive way, until reaching
            its value

        Args:
            cls: class to be converted to dict
        Returns:
            value, a list or a dict
    """
    my_dict = dict()
    if hasattr(cls, 'value'):
        if isinstance(cls, BinaryData):
            return "BinaryData"
        elif cls.value is None:
            return '0' * cls._length
        return cls.value

    elif hasattr(cls, '__class__') or isinstance(cls, list):

        if isinstance(cls, list) and len(cls) > 0:
            new_list = list()
            for cl in cls:
                my_dict2 = dict()
                cvars = vars(cl)
                for var in cvars:
                    if not var.startswith('_'):
                        subcls = getattr(cl, var)
                        my_dict2[var] = convert_class(subcls)
                new_list.append(my_dict2)
                del my_dict2

            return new_list

        else:
            cvars = vars(cls)
            for var in cvars:
                if not var.startswith('_'):
                    subcls = getattr(cls, var)
                    my_dict[var] = convert_class(subcls)

    return my_dict
