import sys
import getopt
import json


def usage(file):
    """ This funcion prints the Usage in case of errors or help needed.
        Always ends after printing this lines below.
    """
    print 'Usage: \n' + str(file) + ' [-p min|full] [-f pcap_filter]' + \
        ' [-F filter_file] [-i dev] [-r pcap_file] '
    print '\t -p [min|full] or --print=[min|full]: print min or full' + \
        ' packet headers. Default: min'
    print '\t -f pcap_filter or --pcap-filter=pcap_filter : add a libpcap' +\
        ' filter'
    print '\t -F sanitizer_file.json or --sanitizer-file=sanitizer_file.json'
    print '\t -i interface or --interface=interface. Default: eth0'
    print '\t -r captured.pcap or --src-file=captured.pcap'
    print '\t -o or --print-ovs : print using ovs-ofctl add-flows format'
    print '\t -h or --help'
    sys.exit(0)


def read_sanitizer(sanitizer_file):
    jfile = open(sanitizer_file, 'ro')
    json_content = json.loads(jfile.read())
    return (json_content)


def get_params(argv):
    # Handle all input params
    letters = 'f:F:i:r:p:oh'
    keywords = ['print=', 'pcap-filter=', 'sanitizer-file=', 'interface=',
                'src-file=', 'print-ovs', 'help']

    # Default Values
    input_filter, sanitizer_file, dev, captured_file = '', '', 'eth0', ''

    try:
        opts, extraparams = getopt.getopt(argv[1:], letters, keywords)
    except getopt.GetoptError as err:
        print str(err)
        usage(argv[0])

    print_options = {'min': 1, 'ovs': 0, 'colors': 0}

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
        else:
            usage(argv[0])

    if len(sanitizer_file) == 0:
        sanitizer = {'allowed_of_versions': {}, 'flowMod_logs': {}}
    else:
        sanitizer = read_sanitizer(sanitizer_file)
    return print_options, input_filter, sanitizer, dev, captured_file
