
import socket 
import struct 
from socket_init import (create_raw_socket, set_promiscuous_mode)
from unpacker import (unpack_ethernet, unpack_ipv4, unpack_tcp, unpack_udp, unpack_icmp)
from display import (display_ethernet, display_ipv4, display_tcp, display_udp, display_icmp, display_payload)

IFACE = "wlo1"
ETH_P_IP = 0X0800 #ETHERTYPE FOR IPV4 
# 0X0806 -> ARP
# 0X86DD -> IPV6

def dispatch_protocol(proto : int, l4_data : bytes):
	if proto == 6:#tcp
		src_port, dest_port, seq, ack, flags, window, payload = unpack_tcp(l4_data)
		display_tcp(src_port, dest_port, seq, ack, flags, window)
		display_payload(payload)
		
	elif proto == 17:#udp
		src_port, dest_port, length, payload = unpack_udp(l4_data)
		display_udp(src_port, dest_port, length)
		display_payload(payload)
	
	elif proto == 1: #icmp
		icmp_type, code, checksum, payload = unpack_icmp(l4_data)
		display_icmp(icmp_type, code, checksum)
		display_payload(payload)		 

def capture_loop(sock: socket.socket):

	print(f"[*] Sniffing on {IFACE} - press Ctrl+C to stop (raises a SIGINT Signal from the OS)")

	while True:	
		raw_frame, _ = sock.recvfrom(65535)
		
		dst_mac, src_mac, ether_type, l3_data = unpack_ethernet(raw_frame)
		display_ethernet(dst_mac, src_mac, ether_type)
		
		if ether_type == ETH_P_IP:
			version, ihl, ttl, proto, checksum, src_ip, dest_ip, l4_data = unpack_ipv4(l3_data)
			display_ipv4(version, ihl, ttl, proto, src_ip, dest_ip)
			dispatch_protocol(proto, l4_data)
	 
def main():
	sock = create_raw_socket(IFACE)
	set_promiscuous_mode(sock, IFACE)
	try:
		capture_loop(sock)
	except KeyboardInterrupt:
		print("\n [*] Capture Stopped....")
	finally:
		sock.close()

#this condition below becomes true when you run the file by it's name directly 
#every python file has a built in variable called __name__ which is equals to how the file is being used 
#if we run the file directly then this variable __name__ = __main__

if __name__ == "__main__":
	main()
