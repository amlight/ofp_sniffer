NET = {}
name = {"cc4e249102000000": "andes2",
        "cc4e249126000000": "andes1",
        "cc4e244b11000000": "sol2",
        "0024389406000000": "mct01",
        "002438af17000000": "mct02"}

def support_fsfw(print_options, lldp):
    global NET

    ip = print_options['device_ip']
    port = print_options['device_port']
    dpid = lldp['c_id'].split(':')[1]

    if len(dpid) < 16:
        # diff = 16 - len(dpid)
        dpid = '00' + dpid

    name = get_name_dpid(dpid)
    NET[ip, port] = name
    return


def get_name_dpid(dpid):
    return '%s' % name.get(dpid)


def get_ip_name(ip, port):
    for i, j in NET.iteritems():
        if i == (ip, port):
            return '%s(%s)' % (ip, j)
    return ip
