"""
    This app process all OF messages to create statistics
    export via REST. Main user is Zabbix and SDN-LG
"""


import json
import time
from datetime import datetime
from _thread import start_new_thread as new_thread
from pyof.foundation.basic_types import BinaryData
from pyof.v0x01.common.header import Type as Type10
from pyof.v0x04.common.header import Type as Type13
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
        for of_type in Type10:
            types['1'][of_type.name] = 0
        types['4'] = dict()
        for of_type in Type13:
            types['4'][of_type.name] = 0

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
            Just return when the ofp_sniffer started
        """
        msg = {'start_time': self.start_time}
        return self.to_json(msg)

    def get_counter(self):
        """
            Get counters via REST
        """
        msg = dict()
        msg['current_time'] = self.get_time()
        msg['total_packets'] = self.num_packets
        msg['per_types'] = self.type_packets
        return self.to_json(msg)

    def get_last_msgs(self):
        """
            Get the last messages seen
        """
        return self.to_json(self.last_msgs.items)

    # Main Method
    def process_packet(self, pkt):
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

            self.last_msgs.add(pkt.l1.time, of_msg.ofp)


class CircularList(object):
    """
        This class only creates a new type: a CircularList.
        The idea is to export the last LIMIT messages via REST.
    """
    LIMIT = 500

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
