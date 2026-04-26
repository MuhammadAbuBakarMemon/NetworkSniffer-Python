import socket 
import fcntl 
import struct

IFACE = "wlo1" #python obj for listening over a WIFI Network in my ubuntu linux machine 

SIOCGIFFLAGS = 0x8913	#sets the interface flags 
SIOCSIFFLAGS = 0x8914	#gets the intergace flags 
IFF_PROMISC = 0x100	#used later on for the bitwise OR operation to set the promiscous [starts reading all the network traffic not the traffic that is only meant for you mac address] bit in the flags

#now we create a raw socket for sniffing/eavesdropping over the network 
def create_raw_socket(iface: str) -> socket.socket:

	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	sock.bind((iface, 0)) #0 matlab no filter on whjat our socket is capturing i.e all packets, not resttricted to IPV4 or ARP or IPV6
	return sock

def set_promiscuous_mode(sock : socket.socket, iface : str) -> None:
	ifreq = struct.pack("16sH22s", iface.encode(), 0, b'\x00' * 22)
	
	ifreq = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
	flags = struct.unpack("16sH22s", ifreq)[1]
	
	flags |= IFF_PROMISC
	
	ifreq = struct.pack("16sH22s", iface.encode(), flags, b'\x00' * 22)
	fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifreq)
