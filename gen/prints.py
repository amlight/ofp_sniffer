"""
    Generic printing functions
"""


from termcolor import colored
import gen.cli


def red(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'red')


def green(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'green')


def blue(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'blue')


def yellow(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'yellow')


def cyan(string):
    if gen.cli.NO_COLOR is True:
        return string
    return colored(string, 'cyan')
