import gen.prints


def red(string):
    return gen.prints.red(string)


def print_hello_elememnts(of_xid, el_type, el_length, count):
    print ('%s Hello - Element: %s Type: %s Length: %s' %
           (of_xid, count, el_type, el_length))


def print_hello_bitmap(of_xid, bitmap):
    print ('%s Hello - Bitmap: %s' % (of_xid, hex(bitmap)))


def print_of_error(of_xid, nameCode, typeCode):
    print ('%s OpenFlow Error - Type: %s Code: %s' %
           (of_xid, red(nameCode), red(typeCode)))


def print_echoreq(of_xid):
    print ('%s OpenFlow Echo Request' % (of_xid))


def print_echores(of_xid):
    print ('%s OpenFlow Echo Reply' % (of_xid))


def print_of_BarrierReq(of_xid):
    print '%s OpenFlow Barrier Request' % of_xid


def print_of_BarrierReply(of_xid):
    print '%s OpenFlow Barrier Reply' % of_xid
