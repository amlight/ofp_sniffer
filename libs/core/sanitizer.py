"""
    Sanitizer Class
"""
import json
import sys
from libs.core.singleton import Singleton
from libs.core.printing import PrintingOptions


class Sanitizer(metaclass=Singleton):

    def __init__(self):
        self.allowed_versions = dict()
        self.filters = dict()

    def read_file(self, sanitizer_file):
        """
            Read the JSON file provided through -F
            Args:
                filters_file: file provided
            Returns:
                json content of the file provided
        """
        try:
            with open(sanitizer_file) as jfile:
                json_content = json.loads(jfile.read())

        except Exception as error:
            msg = 'Error Opening the sanitizer file\n'
            msg += 'Please check your JSON file. Maybe the permission is wrong'
            msg += ' or the JSON syntax is incorrect. Try the following:\n'
            msg += 'cat %s | python -m json.tool'
            print(msg % sanitizer_file)
            print("Error seen: %s" % error)
            sys.exit(0)
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
            PrintingOptions().filters = 1
            self.allowed_of_versions = configs['allowed_of_versions']
            self.filters = configs['filters']
