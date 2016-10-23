"""
    This code handles the CLI parameters
"""


import sys
import getopt
import json
import pcapy
import gen.proxies as proxies


VERSION = '0.3a-dev'
NO_COLOR = False
print_ovs = False
# Change variable below to activate debugging
DEBUGGING = False


def usage(filename):
    """
        This funcion prints the Usage in case of errors or help needed.
        Always ends after printing this lines below.
        Args:
            filename: name of the script called (usually ofp_sniffer.py)
    """
    print (('Usage: \n %s [-p min|full] [-f pcap_filter] [-F filter_file]'
            ' [-i dev] [-r pcap_file]\n'
            '\t -p [min|full] or --print=[min|full]: print min or full'
            ' packet headers. Default: min\n'
            '\t -f pcap_filter or --pcap-filter=pcap_filter : add a libpcap'
            ' filter\n'
            '\t -F sanitizer_file.json or --sanitizer-file=sanitizerfile.json\n'
            '\t -i interface or --interface=interface. Default: eth0\n'
            '\t -r captured.pcap or --src-file=captured.pcap\n'
            '\t -P devices_list.json or --proxy-file=devices_list.json\n'
            '\t -o or --print-ovs : print using ovs-ofctl format\n'
            '\t -h or --help : prints this guidance\n'
            '\t -c or --no-colors: removes colors\n'
            '\t -d or --debug: enable debug\n'
            '\t -v or --version : prints version\n') % filename)

    sys.exit(0)


def read_sanitizer(sanitizer_file):
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
        print msg % sanitizer_file
        print "Error seen: %s" % error
        sys.exit(0)
    return json_content


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
            print "Using file %s " % capfile
            cap = pcapy.open_offline(capfile)
        else:
            print "Sniffing device %s" % dev
            cap = pcapy.open_live(dev, 65536, 1, 0)

    except Exception as exception:
        print "Error: %s" % exception
        print "Exiting..."
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
            cap - pcap object
            position - position to read
            print_options - printing options
            sanitizer - sanitizer filter
    """
    # Handle all input params
    letters = 'f:F:i:r:P:p:ohvcd'
    keywords = ['print=', 'pcap-filter=', 'sanitizer-file=', 'interface=',
                'src-file=', 'print-ovs', 'help', 'version', 'no-colors',
                'proxy-file=']

    # Default Values
    input_filter, sanitizer_file, dev, captured_file = '', '', 'eth0', ''
    opts = None

    try:
        opts, extraparams = getopt.getopt(argv[1:], letters, keywords)
    except getopt.GetoptError as err:
        print str(err)
        usage(argv[0])

    print_options = {'min': 1, 'colors': 0, 'filters': 0, 'proxy': 0}

    for option, param in opts:
        if option in ['-p', '--print']:
            if param == 'full':
                print_options['min'] = 0
            elif param != 'min':
                print 'Use min or full for printing'
                usage(argv[0])
        elif option in ['-f', '--pcap-filter']:
            input_filter = param
        elif option in ['-F', '--sanitizer-file']:
            sanitizer_file = param
        elif option in ['-i', '--interface']:
            dev = param
        elif option in ['-r', '--captured-file']:
            captured_file = param
        elif option in ['-h', '--help']:
            usage(argv[0])
        elif option in ['-o', '--print-ovs']:
            global print_ovs
            print_ovs = True
        elif option in ['-P', '--proxy-file']:
            print_options['proxy'] = param
        elif option in ['-v', '--version']:
            print 'OpenFlow Sniffer version %s' % VERSION
            sys.exit(0)
        elif option in ['-c', '--no-colors']:
            global NO_COLOR
            NO_COLOR = True
        else:
            usage(argv[0])

    if len(sanitizer_file) == 0:
        sanitizer = {'allowed_of_versions': {}, 'filters': {}}
    else:
        print_options['filters'] = 1
        sanitizer = read_sanitizer(sanitizer_file)

    # Load devices' names in case of proxy
    proxies.load_names_file(print_options['proxy'])

    cap, position = start_capture(captured_file, input_filter, dev)

    return cap, position, print_options, sanitizer
