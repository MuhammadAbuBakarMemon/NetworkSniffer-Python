#this does all of that formatted printing for my sniffer 

def display_ethernet(dest_mac, src_mac, ether_type):
	print("\n" + "=" * 60)
	print(f" [ETH] {src_mac} -> {dest_mac} | Ethertype: 0x{ether_type:04X}")
	
def display_ipv4(version, ihl, ttl, proto, src_ip, dest_ip):
	proto_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
	proto_name = proto_map.get(proto, f"UNKNOWN{proto}")
	print(" [IP{version}]  {src_ip} -> {dest_ip} | Proto: {proto_name} TTL: {ttl} IHL: {ihl}B")

def display_tcp(src_port, dest_port, seq, ack, flags, window):
	print(f" [TCP] {src_port} -> {dest_port} | Flags: [{flags}] Seq: {seq} Ack: {ack} Window: {window}")
	
def display_udp(src_port, dest_port, length):
	print(f" [UDP] {src_port} -> {dest_port} | Length: {length}B")
	
def display_icmp(icmp_type, code, checksum):
	type_map = {0:"Echo reply", 3:"Destination Unreachable", 8:"Echo Request", 11:"TTL Exceeded/Expired"}
	type_name = type_map.get(icmp_type, f"UNKNOWN{icmp_type}")
	print(f" [ICMP] {type_name} Code: {code} Checksum: 0x{checksum:04X}")

def display_payload(payload: bytes, max_bytes: int = 64):
#limiting the max_bytes that the payload can display to 64 because we must be mindful of not flooding out terminal
	if not payload:
		return
		
	data = payload[:max_bytes]
	print(f"[PAYLOAD] {len(payload)} bytes -> total (showing {len(data)}):") 
	hex_dump(data) 
	
def hex_dump(data : bytes, width : int = 16):
	
	for m in range(0, len(data), width):
		
		chunk = data[m : m + width]
		
		offset = f"{m:04X}"
		
		hex_col = " ".join(f"{b:02X}" for b in chunk)
		hex_col = hex_col.ljust(width * 3 - 1)
		
		ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

		print(f" {offset} {hex_col} |{ascii_col}|")
