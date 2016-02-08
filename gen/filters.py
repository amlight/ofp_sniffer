'''
    Filters to be used
'''
import gen.tcpip


def filter_OF_version(pkt):
    # Was -F submitted?
    if pkt.print_options['filters'] is 0:
        return False

    # Check if the OpenFlow version is allowed
    name_version = gen.tcpip.get_ofp_version(pkt.of_h['version'])
    supported_versions = []
    for version in pkt.sanitizer['allowed_of_versions']:
        supported_versions.append(version)
    if name_version not in supported_versions:
        return True
    return False


def filter_OF_type(pkt):
    # Was -F submitted?
    if pkt.print_options['filters'] is 0:
        return False

    name_version = gen.tcpip.get_ofp_version(pkt.of_h['version'])
    # OF Types to be ignored through json file (-F)
    rejected_types = pkt.sanitizer['allowed_of_versions'][name_version]
    if pkt.of_h['type'] in rejected_types['rejected_of_types']:
        return True

    return False
