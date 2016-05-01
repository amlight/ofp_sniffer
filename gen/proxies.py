D_ADDR = None
DEST_PORT = None
NET = {}
name = {"cc4e249102000000": "andes2",
        "cc4e249126000000": "andes1",
        "cc4e244b11000000": "sol2",
        "0024389406000000": "mct01",
        "002438af17000000": "mct02",
        "2438af17000000": "mct02",
        "24389406000000": "mct01"}


def insert_ip_port(dest_ip, dest_port):
    global D_ADDR
    global DEST_PORT
    D_ADDR = dest_ip
    DEST_PORT = dest_port


def support_fsfw(lldp):
    global NET

    ip = D_ADDR
    port = DEST_PORT
    try:
        dpid = lldp.c_id.split(':')[1]
    except:
        dpid = lldp.c_id
    name = get_name_dpid(dpid)
    NET[ip, port] = name
    return


def get_name_dpid(dpid):
    sw_name = name.get(dpid)
    if sw_name is not None:
        return sw_name

    return 'OFswitch'


def get_ip_name(ip, port):
    for i, j in NET.iteritems():
        if i == (ip, port):
            return '%s(%s)' % (ip, j)
    return ip