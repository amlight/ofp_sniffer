'''
    Filters to be used
'''
import tcpiplib.tcpip


def filter_of_version(msg):
    # Was -F submitted?
    if msg.print_options['filters'] is 0:
        return False

    # Check if the OpenFlow version is allowed
    name_version = tcpiplib.tcpip.get_ofp_version(msg.of_h['version'])
    supported_versions = []
    for version in msg.sanitizer['allowed_of_versions']:
        supported_versions.append(version)
    if name_version not in supported_versions:
        return True
    return False


def filter_of_type(msg):
    # Was -F submitted?
    if msg.print_options['filters'] is 0:
        return False

    name_version = tcpiplib.tcpip.get_ofp_version(msg.ofp.version)
    # OF Types to be ignored through json file (-F)
    rejected_types = msg.sanitizer['allowed_of_versions'][name_version]
    if msg.ofp.type in rejected_types['rejected_of_types']:
        return True

    return False
