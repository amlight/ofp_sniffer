import sys
import getopt


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
    sys.exit(0)


def get_params(argv):
    # Handle all input params
    letters = 'f:F:i:r:p:'
    keywords = ['print=', 'pcap-filter=', 'sanitizer-file=', 'interface=',
                'src-file=']

    # Default Values
    print_min = 1
    input_filter, sanitizer_file, dev, captured_file = '', '', 'eth0', ''

    try:
        opts, extraparams = getopt.getopt(argv[1:], letters, keywords)
    except getopt.GetoptError as err:
        print str(err)
        usage(argv[0])

    for option, param in opts:
        if option in ['-p', '--print']:
            print_min = param
            if print_min == 'min':
                print_min = 1
            elif print_min == 'full':
                print_min = 0
            else:
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
        else:
            usage(argv[0])

    return print_min, input_filter, sanitizer_file, dev, captured_file
