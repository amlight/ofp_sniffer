"""
    This code is incomplete
    It will be finished on version 0.4
"""

from struct import unpack


def parse_nicira(packet, start, of_xid):
    print ('%s OpenFlow Vendor Data: ' % of_xid),
    while len(packet[start:start+4]) > 0:
        ofv_subtype = unpack('!L', packet[start:start+4])
        print ('%s ' % ofv_subtype[0]),
        start += 4
