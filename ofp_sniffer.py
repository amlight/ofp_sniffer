
from struct import unpack
from termcolor import colored
#import ofp_dissector

def get_ofp_error(type, code):
	if type == 0:
		if code == 0:
			return 'HelloFailed','Incompatible'
		elif code == 1:
			return 'HelloFailed','EPerm'
	elif type == 1:
		if code == 5:
			return 'BadRequest','EPerm'
	elif type == 3:
		if code == 0:
			return 'FlowMod Failed','AllTablesFull'
                if code == 2:
                        return 'FlowMod Failed','Overlap'
                if code == 3:
                        return 'FlowMod Failed','EPerm'
                if code == 4:
                        return 'FlowMod Failed','BadEmergTimeout'
                if code == 5:
                        return 'FlowMod Failed','BadCommand'
                if code == 6:
                        return 'FlowMod Failed','Unsupported'


def print_ofp_match(xid, ofm_wildcards, ofm_in_port, ofm_dl_src, ofm_dl_dst, ofm_dl_vlan,
		   ofm_dl_type, ofm_pcp, ofm_pad, ofm_nw_tos, ofm_nw_prot, ofm_pad2,
		    ofm_nw_src, ofm_nw_dst, ofm_tp_src, ofm_tp_dst):
        
	print str(xid) + ' OpenFlow FLOW_MOD Match - Wildcard: ' + str(ofm_wildcards) \
            + ' in_port: ' + colored(str(ofm_in_port), 'green') + ' dl_src: ' + \
            str(ofm_dl_src) + ' dl_dst: ' + \
            str(ofm_dl_dst) + ' dl_vlan: ' + colored(str(ofm_dl_vlan), 'green') \
            + ' dl_type: ' + colored(str('0x'+format(ofm_dl_type, '02x')), 'green') + \
            ' pcp: ' + str(ofm_pcp) + ' pad: ' + str(ofm_pad) + \
            ' nw_tos: ' + str(ofm_nw_tos) + ' nw_prot: ' + \
            str(ofm_nw_prot) + ' pad2: ' + str(ofm_pad2) + ' nw_src: ' \
            + str(ofm_nw_src) + ' nw_dst: ' + str(ofm_nw_dst) + ' tp_src: '\
            + str(ofm_tp_src) + ' tp_dst: ' + str(ofm_tp_dst)

def get_ofp_command(command):
	if command == 0: return 'Add'
	elif command == 1: return 'Modify'
	elif command == 2: return 'ModifyStrict'
	elif command == 3: return 'Delete'
	else: return 'DeleteStrict'

def get_ofp_flags(flag):
	if flag == 1: return 'SendFlowRem'
	elif flag == 2: return 'CheckOverLap'
	else: return 'Emerg'

def print_ofp_body(xid, ofmod_cookie, ofmod_command,
                             ofmod_idle_timeout, ofmod_hard_timeout,
                             ofmod_prio, ofmod_buffer_id,
                             ofmod_out_port, ofmod_flags):
	print str(xid) + ' OpenFlow FLOW_MOD Body - Cookie: ' + str('0x' + format(ofmod_cookie, '02x')) \
	    + ' Command: ' + colored(get_ofp_command(ofmod_command), 'green') + ' Idle/Hard Timeouts: '\
	    + str(ofmod_idle_timeout) + '/' + str(ofmod_hard_timeout) + ' Priority: '\
	    + str(ofmod_prio) + ' Buffer ID: ' + str('0x' + format(ofmod_buffer_id, '02x')) + ' Out Port: '\
	    + str(ofmod_out_port) + ' Flags: ' + get_ofp_flags(ofmod_flags)

def print_ofp_action(xid, type, length, payload):
	if type == 0:
		type_0 = unpack('!HH', payload)		 
		print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + colored('OUTPUT', 'green') + ' Length: ' + str(length) \
            	    + ' Port: ' + colored(str('CONTROLLER(65533)' if type_0[0] == 65533 else type_0[0]), 'green') + ' Max Length: ' + str(type_0[1])
	elif type == 1:
                type_0 = unpack('!HH', payload)
                print str(xid) + ' OpenFlow FLOW_MOD Action - Type: ' + colored('SetVLANID', 'green') + ' Length: ' + str(length) \
                    + ' VLAN ID: ' + colored(str(type_0[0]), 'green') + ' Pad: ' + str(type_0[1])		
	elif type == 2:
		return 'SetVLANPCP'
	elif type == 3:
		return 'StripVLAN'
	elif type == 4:
		return 'SetDLSrc'
	elif type == 5:
		return 'SetDLDst'
	elif type == 6:
		return 'SetNWSrc'
	elif type == 7:
		return 'SetNWDst'
	elif type == 8:
		return 'SetNWTos'
	elif type == 9:
		return 'SetTPSc'
	elif type == int('a',16):
		return 'SetTPDst'
        elif type == int('b',16):
                return 'Enqueue'
        elif type == int('ffff',16):
                return 'Vendor'
