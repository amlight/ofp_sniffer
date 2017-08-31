"""
    This code handles the CLI parameters
"""


import getopt
import pcapy
import sys
from libs.core.printing import PrintingOptions
from libs.gen.proxies import OFProxy


VERSION = '0.4'
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
           '\t -p : print full headers'
           ' packet headers. Default: min\n'
           '\t -f pcap_filter or --pcap-filter=pcap_filter: add a libpcap'
           ' filter\n'
           '\t -F filters_file.json or --filters-file=filters.json\n'
           '\t -i interface or --interface=interface. Default: eth0\n'
           '\t -r captured.pcap or --src-file=captured.pcap\n'
           '\t -P topology.json or --topology-file=topology.json\n'
           '\t -o or --print-ovs : print using ovs-ofctl format\n'
           '\t -h or --help : prints this guidance\n'
           '\t -c or --no-colors: removes colors\n'
           '\t -v or --version : prints version\n'
           '\t -O or --oess-fvd: monitor OESS FVD status\n'
           '\t -S or --enable-statistics: creates statistics') % filename)

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
        infilter = " port 6633 "
    cap.setfilter(infilter)

    return cap, position


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
    topology_file = 0
    opts = None
    load_apps = []

    # Handle all input params
    letters = 'f:F:i:r:T:pohvcOSq'
    keywords = ['pcap-filter=', 'filters-file=', 'interface=',
                'src-file=', 'print-ovs', 'help', 'version', 'no-colors',
                'topology-file=', 'oess-fvd', 'enable-statistics', 'no-output']

    try:
        opts, extraparams = getopt.getopt(argv[1:], letters, keywords)
    except getopt.GetoptError as err:
        usage(argv[0], err)

    for option, param in opts:
        if option in ['-p']:
            PrintingOptions().min = False
        elif option in ['-f', '--pcap-filter']:
            input_filter = param
        elif option in ['-F', '--filters-file']:
            filters_file = param
        elif option in ['-i', '--interface']:
            dev = param
        elif option in ['-r', '--captured-file']:
            captured_file = param
        elif option in ['-o', '--print-ovs']:
            PrintingOptions().print_ovs = True
        elif option in ['-T', '--topology-file']:
            topology_file = param
        elif option in ['-c', '--no-colors']:
            PrintingOptions().colors = False
        elif option in ['-q', '--no-output']:
            PrintingOptions().set_no_print()
        elif option in ['-O', '--oess-fvd']:
            load_apps.append('oess_fvd')
        elif option in ['-S', '--enable-statistics']:
            load_apps.append('statistics')
        elif option in ['-v', '--version']:
            print('OpenFlow Sniffer version %s' % VERSION)
            sys.exit(0)
        else:
            usage(argv[0])

    # Load switch names
    # TODO: instantiate topology
    OFProxy().load_names_file(topology_file)

    cap, position = start_capture(captured_file, input_filter, dev)

    return cap, position, load_apps, filters_file
