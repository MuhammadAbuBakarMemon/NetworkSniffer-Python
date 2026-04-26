
import socket 
import struct 
from socket_init import (create_raw_socket, set_promiscuos_mode)
from unpacker import (unpack_ethernet, unpack_ipv4, unpack_tcp, unpack_udp, unpack_icmp)
from display import (display_ethernet, diaplay_ipv4, display_icmp, display_tcp, display_udp, display_payload)

IFACE = "wlan0"
ETH_P_IP = 0X0800 #ETHERTYPE FOR IPV4 
# 0X0806 -> ARP
# 0X86DD -> IPV6

def dispatch_protocol(proto L int, 14_data : bytes):
	if proto == 6:#tcp
		src_port, dest_port, seq, ack, flags, window, payload = unpack_tcp(14_data)
		display_tcp(src_port, dest_port seq, ack, flags, window)
		display_payload(payload)
		
	elif proto == 17:#udp
		src_port, dest_port, length, payload = unpack_udp(14_data)
		diaplay_udp(src_port, dest_port, length)
		display_payload(payload)
	
	elif proto == 1:#icmp
		icmp_type, code, checksum, payload = unpck_icmp(14_data)
		display_icmp(icmp_type, code, checksum)
		display_payload(payload)		 

def capture_loop(sock: socket.socket):
	print(f"[*] Sniffing on {IFACE} - press Ctrl+C to stop (raises a SIGINT Signal from the OS)")
	
	raw_frame, _ = sock.recvfrom(65535)
	
	dst_mac, src_mac, ether_type, 13_data = unpack_ethernet(raw_frame)
	display_ethernet(dst_mac, src_mac, ethertype)
	
	if ethertype == ETH_P_IP:
		version, ihl, ttl, proto, checksum, src_ip, dest_ip, 14_data = unpack_ipv4(13_data)
		display_ipv4(version, ihl, ttl, proto, src_ip, dest_ip)
		dispatch_protocol(proto, 14_data)
	 
def main():
	sock = create_raw_socket(IFACE)
	set_promiscuous_mode(sock, IFACE)
	try:
		capture_loop(sock)
	except KeyboardInterrupt:
		print("\n[*] Capture Stopped....")
	finally:
		sock.close()

#this condition below becomes true when you run the file by it's name directly 
#every python file has a built in variable called __name__ which is equals to how the file is being used 
#if we run the file directly then this variable __name__ = __main__

if __name__ == "__main__":
	main()
