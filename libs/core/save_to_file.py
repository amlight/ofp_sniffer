"""
    This module is used to redirect all output to a file.
    File rotation is possible based on file size.
"""


import sys
from datetime import datetime
from libs.core.singleton import Singleton
from libs.core.printing import PrintingOptions


def save_to_file(log_file):
    """
        Change default output to be SaveFile()
    """
    if len(log_file) is not 0:
        sys.stdout = SaveFile(log_file)


class SaveFile(metaclass=Singleton):
    """
        Redirects the content to be printed
        to also be a file.
    """

    def __init__(self, log_file):
        """
            Initialize two main descriptors: terminal and log.
            Terminal will be responsible to print to the CLI and
            Log will be responsible to print to file.
            If user provides a -q (quiet), but provides a -w,
            nothing will be printed on terminal.
        """
        if PrintingOptions().is_quiet():
            self.terminal = None  # Dont Print to Terminal
            PrintingOptions().set_no_quiet()
        else:
            self.terminal = sys.stdout  # Print to Terminal
        self.log = RotateFile(log_file)  # Print to File

    def write(self, message):
        """
            Write to file and to terminal

            Args:
                message: message to print
        """
        if self.terminal:
            self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        """
            Flush file
        """
        self.log.flush()


class RotateFile(metaclass=Singleton):
    """
        This class is responsible for rotating the log file
        once it gets close to the size predefined below.

        The filename provided by the user via CLI is always
        concatenated with the timestamp of its creation to
        avoid overlapping and easy retrieval.
    """
    ROTATE_AT = 10485760  # in Bytes - Default 10MB

    def __init__(self, filename):
        self.filename = filename
        self.log = self.set_file()
        self.total = 0

    def set_file(self):
        """
            Add the timestamp to filename and open the
            file. Return the file descriptor.
        """
        time = self.get_current_time()
        filename = "%s-%s" % (self.filename, time)
        log = open(filename, "a")
        return log

    def rotate_file(self):
        """
            If file got close to ROTATE_AT, close the
            file and create a new one.
        """
        self.log.close()
        self.log = self.set_file()
        self.total = 0

    @staticmethod
    def get_current_time():
        """
            Return current time in a specific format
        """
        now = datetime.utcnow()
        return datetime.strftime(now, '%Y%m%d%H%M%S')

    def write(self, msg):
        """
            Write message to the log file

            Args:
                msg: text to be saved
        """
        if self.total >= self.ROTATE_AT:
            self.rotate_file()

        self.total += self.log.write(msg)

    def flush(self):
        """
            Flush file
        """
        self.log.flush()
