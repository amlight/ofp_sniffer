from gen.tcpip import get_ethernet_frame, get_ip_packet, get_tcp_stream, \
    get_openflow_header
from of10.parser import process_ofp_type
import gen.prints
import of10.prints


IP_PROTOCOL = 8
TCP_PROTOCOL = 6
TCP_FLAG_PUSH = 8
OF_HEADER_SIZE = 8


class Packet:
    '''
        Used to save all data about the packet
    '''
    def __init__(self, packet, print_options, sanitizer):
        self.l1 = {}
        self.l2 = {}
        self.l3 = {}
        self.l4 = {}
        self.of_h = {}
        self.of_body = {}
        self.packet = packet
        self.openflow_packet = False
        self.offset = 0
        self.print_options = print_options
        self.sanitizer = sanitizer
        self.printing_seq = []

    def seq_of_print(self, function):
        self.printing_seq.append(function)

    def process_header(self, captured_size, truncated_size, now):
        self.process_l1(captured_size, truncated_size, now)
        self.process_l2()
        if self.l2['protocol'] == IP_PROTOCOL:
            self.process_l3()
            if self.l3['protocol'] == TCP_PROTOCOL:
                self.process_l4()
                if self.l4['flag_psh'] == TCP_FLAG_PUSH:
                    self.openflow_packet = True

        return self.openflow_packet

    def process_l1(self, captured_size, truncated_size, now):
        self.l1 = {'caplen': captured_size, 'truncate_len': truncated_size,
                   'time': now}

    def process_l2(self):
        self.l2 = get_ethernet_frame(self.packet)
        self.offset = self.l2['length']

    def process_l3(self):
        self.l3 = get_ip_packet(self.packet, self.offset)
        self.offset += self.l3['length']

    def process_l4(self):
        self.l4 = get_tcp_stream(self.packet, self.offset)
        self.offset += self.l4['length']
        # Avoid this:
        self.print_options['device_ip'] = self.l3['d_addr']
        self.print_options['device_port'] = self.l4['dest_port']

    def process_openflow_header(self):
        self.of_h = get_openflow_header(self.packet, self.offset)
        self.offset += 8

    def get_remaining_bytes(self):
        return self.l1['caplen'] - self.offset

    def process_openflow_body(self):
        self.remaining_bytes = self.get_remaining_bytes()
        self.start = self.offset
        while (self.remaining_bytes >= 8):
            self.process_openflow_header()
            self.remaining_bytes -= self.of_h['length']
            self.start += OF_HEADER_SIZE
            self.end = self.of_h['length'] - OF_HEADER_SIZE
            self.this_packet = self.packet[self.start:self.start+self.end]
            # debug
            # print self.of_h['type']
            if self.of_h['version'] is 1:
                if not process_ofp_type(self):
                    of10.prints.print_type_unknown(self)
                    return
                else:
                    # Print packets
                    self.print_packet()
                    self.start += (self.of_h['length'] - OF_HEADER_SIZE)
        # print

    def prepare_printing(self, string, values):
        self.of_body[string] = values
        self.seq_of_print(string)

    def print_packet(self):
        if not self.check_filters():
            gen.prints.print_headers(self)
            gen.prints.print_openflow_header(self.of_h)
            if self.of_h['version'] is 1:
                of10.prints.print_body(self)
#            elif self.of_h['version'] is 4:
#                print of13.prints.print_body(self)
            print

    def check_filters(self):
        # Was -F submitted?
        if self.print_options['filters'] is 0:
            return False
        # Check if there is any limitation for printing
        name_version = gen.tcpip.get_ofp_version(self.of_h['version'])
        supported_versions = []
        for version in self.sanitizer['allowed_of_versions']:
            supported_versions.append(version)
        if name_version not in supported_versions:
            return True

        # OF Types to be ignored through json file (-F)
        rejected_types = self.sanitizer['allowed_of_versions'][name_version]
        if self.of_h['type'] in rejected_types['rejected_of_types']:
            return True
