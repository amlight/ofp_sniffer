"""
    Generic printing: colors
"""


from termcolor import colored
from libs.core.printing import PrintingOptions


def red(string):
    """
        If PrintingOptions().colors, prints string
        in the color RED

        Args:
            string: text to be printed
    """
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'red')


def green(string):
    """
        If PrintingOptions().colors, prints string
        in the color GREEN

        Args:
            string: text to be printed
    """
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'green')


def blue(string):
    """
        If PrintingOptions().colors, prints string
        in the color BLUE

        Args:
            string: text to be printed
    """
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'blue')


def yellow(string):
    """
        If PrintingOptions().colors, prints string
        in the color YELLOW

        Args:
            string: text to be printed
    """
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'yellow')


def cyan(string):
    """
        If PrintingOptions().colors, prints string
        in the color CYAN

        Args:
            string: text to be printed
    """
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'cyan')
