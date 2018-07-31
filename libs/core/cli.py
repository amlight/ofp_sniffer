#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    This code handles the CLI parameters
"""


import sys
import getopt
import pcapy
from libs.core.printing import PrintingOptions


VERSION = '1.2'
# Change variable below to activate debugging
DEBUGGING = False


def usage(filename, msg=None):
    """
        This funcion prints the Usage in case of errors or help needed.
        Always ends after printing this lines below.
        Args:
            filename: name of the script called (usually ofp_sniffer.py)
            msg: an error msg
    """
    if msg is not None:
        print(msg)

    print(('Usage: \n %s [-p min|full] [-f pcap_filter] [-F filter_file]'
           ' [-i dev] [-r pcap_file]\n'
           '\t -p : print all TCP/IP headers. Default: min\n'
           '\t -f pcap_filter or --pcap-filter=pcap_filter: add a libpcap'
           ' filter\n'
           '\t -F filters_file.json or --filters-file=filters.json\n'
           '\t -i interface or --interface=interface. Default: eth0\n'
           '\t -r captured.pcap or --src-file=captured.pcap\n'
           '\t -T topology.json or --topology-file=topology.json\n'
           '\t -w file or --save-to-file=file: save output to file provided'
           '\t -o or --print-ovs : print using ovs-ofctl format\n'
           '\t -h or --help : prints this help\n'
           '\t -c or --no-colors: removes colors\n'
           '\t -v or --version : prints version\n'
           '\t -q or --no-output : do not print anything\n'
           '\t -O WARN:CRIT or --oess-fvd=WARN:CRIT: monitor OESS FVD status\n'
           '\t -S or --enable-statistics: creates statistics\n'
           '\t -N or --notify-via-slack: send notifications via Slack. Param is channel name\n'
           '\t -I or --enable-influx: enables influxdb. Only works if -S is enabled') % filename)

    sys.exit(0)


def check_file_position(filename):
    """
        Check if -r file was inserted with colon (:)
        If yes, only read the position specified after colon
    Args:
        filename: User's input -r
    Returns:
        position number
    """
    new_file = filename.partition(":")[0]
    position = filename.partition(":")[2]
    return new_file, int(position) if len(position) is not 0 else 0


def start_capture(capfile, infilter, dev):
    """
        With all information in hand, start capturing packets
        Args:
            capfile: in case user provides a pcap file
            infilter: any tcpdump filters
            dev: network device to sniffer
        Returns:
            cap object
            position number
    """
    position = 0
    try:
        if len(capfile) > 0:
            capfile, position = check_file_position(capfile)
            print("Using file %s " % capfile)
            cap = pcapy.open_offline(capfile)
        else:
            print("Sniffing device %s" % dev)
            cap = pcapy.open_live(dev, 65536, 1, 0)

    except Exception as exception:
        print("Error: %s" % exception)
        print("Exiting...")
        sys.exit(3)

    if len(infilter) is 0:
        # Super specific filter to overcome the python-pcapy performance issue
        # reported on https://github.com/CoreSecurity/pcapy/issues/12
        infilter = "tcp and port 6633 and (tcp[13] & 8!=0 or (tcp[13] & 1!=0 and tcp[13] & 16!=0))"

    cap.setfilter(infilter)

    return cap, position


def read_params(argv):
    """
        Parser params received via CLI

        Args:
            argv: inputs
        Return:
            opts: getopt object
    """
    letters = 'f:F:i:r:T:w:O:N:pohvcSqI'
    keywords = ['pcap-filter=', 'filters-file=', 'interface=',
                'src-file=', 'print-ovs', 'help', 'version', 'no-colors',
                'topology-file=', 'oess-fvd=', 'enable-statistics', 'enable-influx',
                'no-output', 'save-to-file', 'notify-via-slack=']

    try:
        opts, _ = getopt.getopt(argv[1:], letters, keywords)
        return opts
    except getopt.GetoptError as err:
        usage(argv[0], err)


def get_params(argv):
    """

        Get CLI params provided by user
        Args:
            argv: CLI params
        Returns:
            cap: pcap object
            position: packet number to read
            load_apps: apps to load
            filters_file: filters
    """
    # Default Values
    input_filter, filters_file, dev, captured_file = '', '', 'eth0', ''
    save_file = ''
    topology_file = "./docs/topology.json"
    load_apps = dict()

    opts = read_params(argv)

    for option, param in opts:
        if option in ['-p']:
            PrintingOptions().set_full_headers()
        elif option in ['-f', '--pcap-filter']:
            input_filter = param
        elif option in ['-F', '--filters-file']:
            filters_file = param
        elif option in ['-i', '--interface']:
            dev = param
        elif option in ['-r', '--captured-file']:
            captured_file = param
        elif option in ['-o', '--print-ovs']:
            PrintingOptions().set_print_ovs()
        elif option in ['-T', '--topology-file']:
            topology_file = param
        elif option in ['-c', '--no-colors']:
            PrintingOptions().set_no_color()
        elif option in ['-q', '--no-output']:
            PrintingOptions().set_no_print()
        elif option in ['-O', '--oess-fvd']:
            load_apps['oess_fvd'] = param
        elif option in ['-S', '--enable-statistics']:
            load_apps['statistics'] = 0
        elif option in ['-I', '--enable-influx']:
            load_apps['influx'] = 0
        elif option in ['-w', '--save-to-file']:
            save_file = param
        elif option in ['-v', '--version']:
            print('OpenFlow Sniffer version %s' % VERSION)
            sys.exit(0)
        elif option in ['-N', '--notify-via-slack']:
            load_apps['notifications'] = param
        else:
            usage(argv[0])

    cap, position = start_capture(captured_file, input_filter, dev)

    return cap, position, load_apps, filters_file, topology_file, save_file
