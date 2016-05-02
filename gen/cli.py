import sys
import getopt
import json
import pcapy


VERSION = '0.3a-dev'
NO_COLOR = False


def usage(file):
    """ This funcion prints the Usage in case of errors or help needed.
        Always ends after printing this lines below.
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
            '\t -o or --print-ovs : print using ovs-ofctl format\n'
            '\t -h or --help : prints this guidance\n'
            '\t -c or --no-colors: removes colors\n'
            '\t -d or --debug: enable debug\n'
            '\t -v or --version : prints version\n') % file)

    sys.exit(0)


def read_sanitizer(sanitizer_file):
    try:
        jfile = open(sanitizer_file, 'ro')
        json_content = json.loads(jfile.read())
    except:
        msg = 'Error Opening the sanitizer file\n'
        msg += 'Please check your JSON file. Maybe the permission is wrong'
        msg += ' or the JSON syntax is incorrect. Try the following:\n'
        msg += 'cat %s | python -m json.tool'
        print msg % sanitizer_file
        sys.exit(0)
    return (json_content)


def check_file_position(file):
    """
        Check if -r file was inserted with colon (:)
        If yes, only read the position specified after colon
    Args:
        file: User's input -r
    Returns:
        position
    """
    new_file = file.partition(":")[0]
    position = file.partition(":")[2]
    return new_file, int(position) if len(position) is not 0 else 0


def start_capture(capfile, infilter, dev):
    try:
        if len(capfile) > 0:
            capfile, position = check_file_position(capfile)
            print "Using file %s " % capfile
            cap = pcapy.open_offline(capfile)
        else:
            print "Sniffing device %s" % dev
            cap = pcapy.open_live(dev, 65536, 1, 0)

    except Exception as exception:
        print exception
        return -1

    finally:
        if len(infilter) is 0:
            infilter = " port 6633 "
            cap.setfilter(infilter)
        return cap, position


def get_params(argv):
    # Handle all input params
    letters = 'f:F:i:r:p:ohvcd'
    keywords = ['print=', 'pcap-filter=', 'sanitizer-file=', 'interface=',
                'src-file=', 'print-ovs', 'help', 'version', 'no-colors',
                'debug']

    # Default Values
    input_filter, sanitizer_file, dev, captured_file = '', '', 'eth0', ''

    try:
        opts, extraparams = getopt.getopt(argv[1:], letters, keywords)
    except getopt.GetoptError as err:
        print str(err)
        usage(argv[0])

    print_options = {'min': 1, 'debug': 0, 'ovs': 0, 'colors': 0, 'filters': 0}

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
            print_options['ovs'] = 1
        elif option in ['-v', '--version']:
            print 'OpenFlow Sniffer version %s' % VERSION
            sys.exit(0)
        elif option in ['-c', '--no-colors']:
            global NO_COLOR
            NO_COLOR = True
        elif option in ['-d', '--debub']:
            print_options['debug'] = 1
        else:
            usage(argv[0])

    if len(sanitizer_file) == 0:
        sanitizer = {'allowed_of_versions': {},
                     'filters': {}}
    else:
        print_options['filters'] = 1
        sanitizer = read_sanitizer(sanitizer_file)


    cap, position = start_capture(captured_file, input_filter, dev)

    return cap, position, print_options, sanitizer
