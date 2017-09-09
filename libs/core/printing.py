"""
    Class with CLI printing options
"""


from libs.core.singleton import Singleton


class PrintingOptions(metaclass=Singleton):
    """
        This is a Singleton class for all printing
        options.
    """

    def __init__(self):
        self._min = True  # print minimal headers
        self._colors = True  # print colors
        self._filters = False  # apply filters
        self._print_ovs = False  # print ovs format
        self._quiet = False  # don't print anything

    def is_minimal_headers(self):
        """
            Return true if user opted to print only
            minimal headers
        """
        if self._min:
            return True
        return False

    def set_minimal_headers(self):
        """
            Set to print only one line for the
            TCP/IP stack
        """
        self._min = True

    def set_full_headers(self):
        """
            Set to print all TCP/IP headers
        """
        self._min = False

    def has_filters(self):
        """
            If there are filters to apply before
            printing anything
        """
        if self._filters:
            return True
        return False

    def set_filtering(self):
        """
            If there are filters to apply before
            printing anything, set to True
        """
        self._filters = True

    def set_print_ovs(self):
        """
            Print OVS-equivalent messages
        """
        self._print_ovs = True

    def set_no_print(self):
        """
            Set to avoiding printing.
        """
        self._quiet = True

    def is_quiet(self):
        """
            Return self.quiet
        """
        if self._quiet:
            return True
        return False

    def set_quiet(self):
        """
            Set quiet mode - don't print anything
        """
        self._quiet = True

    def set_no_quiet(self):
        """
            Set to no quiet mode
        """
        self._quiet = False

    def is_colored(self):
        """
            Return self.colors
        """
        if self._colors:
            return True
        return False

    def set_no_color(self):
        """
            Set black and white mode
        """
        self._colors = False

    def set_color(self):
        """
            Set black and white mode
        """
        self._colors = True
