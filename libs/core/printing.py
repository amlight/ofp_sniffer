"""
    Class with CLI printing options
"""
from libs.core.singleton import Singleton


class PrintingOptions(metaclass=Singleton):
    """
        This is a Singleton class with all printing
        options.
    """

    def __init__(self):
        self.min = 1  # print minimal headers
        self.colors = True  # print colors
        self.filters = 0  # apply filters
        self.proxy = 0  # add proxy support
        self.print_ovs = False  # print ovs format
        self.quiet = False  # don't print anything

    def set_no_print(self):
        """
            Set to avoiding printing.
        """
        self.quiet = True
