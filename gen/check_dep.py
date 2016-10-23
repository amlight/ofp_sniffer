import imp
import os


def check_if_root():
    if os.geteuid() != 0:
        print("You need to have root privileges to run this script.")
        print("Please try again, this time using 'sudo'. Exiting.")
        return False
    return True


def check_dependencies():
    found = True

    with open('docs/requirements.txt') as dependencies:
        for dependency in dependencies:
            try:
                imp.find_module(dependency.rstrip('\n'))
            except ImportError:
                print('Module %s missing. Please install it' % dependency.rstrip('\n'))
                print('sudo pip install -r docs/requirements.txt')
                found = False
            except IOError:
                print('docs/requirements.txt file not found')
                found = False
    if found is False:

        return False

    if not check_if_root():
        return False

    return True