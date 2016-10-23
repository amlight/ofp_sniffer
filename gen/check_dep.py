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
                imp.find_module(dependency)
            except ImportError:
                found = False
    if found is False:
        print('Modules missing. Please install them:')
        print('sudo pip install -r docs/requirements.txt')
        return False

    if not check_if_root():
        return False

    return True