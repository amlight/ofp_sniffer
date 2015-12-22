def print_hello_elememnts(of_xid, el_type, el_length, count):
    print ('%s Hello - Element: %s Type: %s Length: %s' %
           (of_xid, count, el_type, el_length))


def print_hello_bitmap(of_xid, bitmap):
    print ('%s Hello - Bitmap: %s' % (of_xid, hex(bitmap)))
