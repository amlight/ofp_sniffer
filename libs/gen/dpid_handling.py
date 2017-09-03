"""
 This module does all DPID cleaning needed by all other modules,
 such as removing substrings 'dpid:', removing ':' and others
"""


def clear_dpid(dpid):
    """
        clear_dpid removes any non useful info from DPID. Some
        examples of DPIDs:

        "dpid:11:11:11:11:11:11"
        "dp:11:11:11:11:11:11"
        "11:11:11:11:11:11"
        "111111111111"

        The goal is to return the last one: "111111111111"

        Args:
            dpid: dpid to be fixed

        Returns:
            dpid fixed

        >>> clear_dpid("dpid:11:11:11:11:11:11")
        '111111111111'
        >>> clear_dpid("dp:11:11:11:11:11:11")
        '111111111111'
        >>> clear_dpid("11:11:11:11:11:11")
        '111111111111'
        >>> clear_dpid("111111111111")
        '111111111111'
    """
    dpid_names = ["dpid:", "dp:"]

    for dpid_name in dpid_names:
        pos = dpid.find(dpid_name)
        if pos != -1:
            # substring found
            dpid = dpid[pos+len(dpid_name):]

    if len(dpid.split(":")) == 2:
        return dpid.split(":")[1]

    elif len(dpid.split(":")) > 2:
        return dpid.replace(":", "")

    return dpid
