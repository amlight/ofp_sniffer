#!/usr/bin/python -d


def process_dst_subnet(wcard):
    OFPFW_NW_DST_SHIFT = 14
    OFPFW_NW_DST_MASK = 1032192
    nw_dst_bits = (wcard & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT
    return ((32 - nw_dst_bits) if nw_dst_bits < 32 else 0)


def process_src_subnet(wcard):
    OFPFW_NW_SRC_SHIFT = 8
    OFPFW_NW_SRC_MASK = 16128
    nw_src_bits = (wcard & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT
    return ((32 - nw_src_bits) if nw_src_bits < 32 else 0)


def convert(wcard):
    if wcard == 1:
        print "  in_port is wildcarded"
    elif wcard == 2:
        print "  dl_vlan is wildcarded"
    elif wcard == 4:
        print "  dl_src is wildcarded"
    elif wcard == 8:
        print "  dl_dst is wildcarded"
    elif wcard == 16:
        print "  dl_type is wildcarded"
    elif wcard == 32:
        print "  nw_prot is wildcarded"
    elif wcard == 64:
        print "  tp_src is wildcarded"
    elif wcard == 128:
        print "  tp_dst is wildcarded"
    elif wcard == 1048576:
        print "  dl_vlan_pcp is wildcarded"
    else:
        print "  nw_tos is wildcarded"


a = int(raw_input())

if a == ((1 << 22) - 1):
    print "All fields are wildcarded"
else:
    for i in range(0, 8):
        mask = 2**i
        aux = a & mask
        if aux != 0:
            convert(mask)

    for i in range(20, 22):
        mask = 2**i
        aux = a & mask
        if aux != 0:
            convert(mask)
    print 'OFPFW_NW_SRC_MASK = /%d' % (process_src_subnet(a))
    print 'OFPFW_NW_DST_MASK = /%d' % (process_dst_subnet(a))
