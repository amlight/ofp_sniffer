"""
    Class with CLI printing options
"""
from libs.singleton import Singleton


class PrintingOptions(metaclass=Singleton):

    def __init__(self):
        self.min = 1
        self.colors = True
        self.filters = 0
        self.proxy = 0
        self.print_ovs = None
