"""
    Generic printing: colors
"""


from termcolor import colored
from libs.core.printing import PrintingOptions


def red(string):
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'red')


def green(string):
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'green')


def blue(string):
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'blue')


def yellow(string):
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'yellow')


def cyan(string):
    if PrintingOptions().colors is False:
        return string
    return colored(string, 'cyan')
