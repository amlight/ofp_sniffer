"""
    Sanitizer Class
"""
import sys
import json
from libs.singleton import Singleton
from libs.printing import PrintingOptions


class Sanitizer(metaclass=Singleton):

    def __init__(self):
        self.allowed_versions = dict()
        self.filters = dict()

    def read_file(self, sanitizer_file):
        """
            Read the JSON file provided through -F
            Args:
                sanitizer_file: file provided
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

    def process_filters(self, sanitizer_file):
        """

        """
        if len(sanitizer_file) == 0:
            return
        configs = self.read_file(sanitizer_file)
        if len(configs) != 0:
            PrintingOptions().filters = 1
            self.allowed_versions = configs['allowed_versions']
            self.filters = configs['filters']
