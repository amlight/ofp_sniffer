"""

"""
import libs.openflow.of10.packet
import libs.openflow.of13.packet


def instantiate_msg(of_header):
    """

    """
    if of_header['version'] is 1:
        return libs.openflow.of10.packet.instantiate(of_header)

    elif of_header['version'] is 4:
        return libs.openflow.of13.packet.instantiate(of_header)

    else:
        return 0
