"""
    Filters/Sanitizer Class
    Used for filtering specific OpenFlow versions and
    message types. Filters are provided via JSON file
    in the cli with option -F or --filters-file
"""


import json
from libs.core.singleton import Singleton
from libs.core.printing import PrintingOptions
from libs.core.custom_exceptions import *


class Sanitizer(metaclass=Singleton):
    """
        Filters/Sanitizer Class
        Used for filtering specific OpenFlow versions and
        message types. Filters are provided via JSON file
        in the cli with option -F or --filters-file
    """

    def __init__(self):
        self.allowed_of_versions = dict()
        self.filters = dict()

    @staticmethod
    def read_file(filters_file):
        """
            Read the JSON file provided through -F
            Args:
                filters_file: file provided
            Returns:
                json content of the file provided
        """
        try:
            with open(filters_file) as jfile:
                json_content = json.loads(jfile.read())

        except JSONDecodeError:
            msg = 'Error opening the sanitizer file. '
            msg += 'Please check your JSON filter file.\n'
            msg += 'Maybe the permission is wrong '
            msg += 'or the JSON syntax is incorrect. \n'
            msg += 'Try the following: '
            msg += 'cat %s | python -m json.tool' % filters_file
            raise ErrorFilterFile(msg)

        return json_content

    def process_filters(self, filters_file):
        """
            If -F file is provided, read the file and import all filters.
            Args:
                filters_file: file with filters

        """
        if len(filters_file) == 0:
            return

        configs = self.read_file(filters_file)
        if len(configs) != 0:
            PrintingOptions().set_filtering()
            self.allowed_of_versions = configs['allowed_of_versions']
            self.filters = configs['filters']
