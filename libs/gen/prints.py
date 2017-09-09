"""
    Generic printing: colors
"""


from termcolor import colored
from libs.core.printing import PrintingOptions


def red(string):
    """
        If PrintingOptions().is_colored, prints string
        in the color RED

        Args:
            string: text to be printed
    """
    if not PrintingOptions().is_colored():
        return string
    return colored(string, 'red')


def green(string):
    """
        If PrintingOptions().is_colored, prints string
        in the color GREEN

        Args:
            string: text to be printed
    """
    if not PrintingOptions().is_colored():
        return string
    return colored(string, 'green')


def blue(string):
    """
        If PrintingOptions().is_colored, prints string
        in the color BLUE

        Args:
            string: text to be printed
    """
    if not PrintingOptions().is_colored():
        return string
    return colored(string, 'blue')


def yellow(string):
    """
        If PrintingOptions().is_colored, prints string
        in the color YELLOW

        Args:
            string: text to be printed
    """
    if not PrintingOptions().is_colored():
        return string
    return colored(string, 'yellow')


def cyan(string):
    """
        If PrintingOptions().is_colored, prints string
        in the color CYAN

        Args:
            string: text to be printed
    """
    if not PrintingOptions().is_colored():
        return string
    return colored(string, 'cyan')
