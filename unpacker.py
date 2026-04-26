#this is probbaly the longest file length wise that I'm gonna code but lessgo 
'''Also a design level change is to be observed that when I made the initial plan from Claude regarding the structure there was a file that went by the name of utilities.py 
when i started implementing what I wanted to make I found out that
it would e just better to have those formatting functions in here like right beneath the unpackers that way they'd be more readale   
'''

import struct



# MOVING ONTO LAYER 2 OF THE OSI MODEL - DATA LINK LAYER
 
ETH_HEADER_LEN = 14

def unpack_ethernet(raw_frame : bytes) -> tuple:
	
	#sliced out the ethernet header
	header = raw_frame[:ETH_HEADER_LEN]
	
	dst_mac_raw, src_mac_raw, ether_type = struct.unpack("6s6sH", header)  
	
	dst_mac = format_mac(dst_mac_raw)
	src_mac = format_mac(src_mac_raw)
	
	payload = raw_frame[:ETH_HEADER_LEN]
	
	return dst_mac, src_mac, ether_type, payload

def format_mac(raw_bytes : bytes) -> str:
	return ":".join(f"{b:02X}" for b in raw_bytes).upper()

IPV4_HEADER_MIN = 20 #this is the minimum length in bytes depanding upon the options the length can exceede 


def unpack_ipv4(raw_packet : bytes) -> tuple:
	
	header = raw_packet[:IPV4_HEADER_MIN]
	
	(ver_ihl, dscp, total_len, pkt_id, flag_frag, ttl, proto, checksum, src_ip_raw, dest_ip_raw) = struct.unpack("!BBHHHBBH4s4s", header)
	
	version = ver_ihl >> 4;
	ihl = (ver_ihl & 0x0F) #this is in 32-bit words
	ihl_bytes = ihl * 4
	
	dest_ip = format_ip(dest_ip_raw)
	src_ip = fromat_ip(src_ip_raw)
	
	payload = raw_bytes[ihl_bytes:]
	
	return version, ihl_bytes, ttl, proto, dest_ip, checksum, src_ip, dest_ip, payload
	
def format_ip(raw_bytes : bytes) -> str:
	return ".".join(str(b) for b in raw_bytes)
  
def unpack_tcp(raw_segment : bytes) -> tuple:
	
	header = raw_segment[:20]
	
	(src_port, dest_port, seq, ack, offset_flags, window, checksum, urg_ptr) = struct.unpack("!HHLLHHHH", header)
	
	data_offset = (offset_flags >> 12) * 4
	flags_raw = (offset_flags & 0x01FF)
	flags_str = parse_tcp_flags(flags_raw)
	
	payload = raw_segment[data_offset : ]
	
	return src_port, dest_port, seq, ack, flags_str, window, payload
	
def parse_tcp_flags(flags : int) -> str:
	flag_map = [(0x100, "URG"), (0x080, "ACK"), (0x040, "PSH"), (0x020, "RST"), (0x010, "SYS"), ("0x008", "FIN")]
	
	#return " ".join(name for mask, name in flag_map if flags & mask) 
	#alternate approach
	
	names = []
	
	for mask, name in flag_map:
		if flags & mask:
			names.append(name)
	
	return " ".join(names)

def unpack_udp(raw_segment : bytes) -> tuple:
	header = raw_segment[:8]
	
	(src_port, dest_port, lenght, checksum) = struct.unpack("!HHHH", header)
	
	payload = raw_segment[8:]
	return src_port, dest_port, lenght, payload	

def unpack_icmp(raw_segment : bytes) -> tuple:
	header = raw_segment[:8]
	
	(icmp_type, code, checksum, rest) = struct.unpack("!BBH4s")
	
	payload = raw_segment[8:]
	
	return icmp_type, code, checksum, payload
	
"""
ICMP TYPE REFERENCE 

0  ->  ECHO REPLY (PING RESPONSE)
3  ->  DESTINATION UNREACHALE 
8  ->  ECHO REQUEST (PING)
11 ->  TTL EXPIRED - TIME EXPIRED 


"""

