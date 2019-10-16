import os
import sys
import datetime
from scapy.all import *
from ipaddress import *

mac_table = {}
tcp_syn_activities = []
tcp_synack_activities = []
icmp_pod_activities = []
icmp_smurf_activities = []

def clear_screen():
	if "linux" in sys.platform:
		os.system("clear")
	elif "win32" in sys.platform:
		os.system("cls")
	else:
		pass

def analyze(pkt):
	global mac_table
	src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, tcp_flags, icmp_type, load_data, load_len = None, None, None, None, None, None, None, None, None, None
	protocol = []
	
	if Ether in pkt[0]:
		src_mac = pkt[0][Ether].src
		dst_mac = pkt[0][Ether].dst
	
	if IP in pkt[0]:
		src_ip = pkt[0][IP].src
		dst_ip = pkt[0][IP].dst
	
	if TCP in pkt[0]:
		protocol.append("TCP")
		src_port = pkt[0][TCP].sport
		dst_port = pkt[0][TCP].dport
		tcp_flags = p[0][TCP].flags.flagrepr()
	
	if UDP in pkt[0]:
		protocol.append("UDP")
		src_port = pkt[0][UDP].sport
		dst_port = pkt[0][UDP].dport
	
	if ICMP in pkt[0]:
		protocol.append("ICMP")
		icmp_type = pkt[0][ICMP].type # 8 for echo-request and 0 for echo-reply
	
	if Raw in pkt[0]:
		load_data = pkt[0][Raw].load
		load_len = len(pkt[0][Raw].load)

	if ARP in pkt[0] and pkt[0][ARP].op in (1,2):
		protocol.append("ARP")
		if pkt[0][ARP].hwsrc not in mac_table.keys():
			mac_table[pkt[0][ARP].hwsrc] = pkt[0][ARP].psrc

	if src_ip == my_ip and src_mac != my_mac and ICMP in pkt[0]:
		icmp_smurf_activities.append([pkt[0].time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_data, load_len])
	if ICMP in pkt[0] and load_len>10240:
		icmp_pod_activities.append([pkt[0].time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_data, load_len])
	if TCP in pkt[0] and tcp_flags == "S" and dst_ip == my_ip:
		tcp_syn_activities.append([pkt[0].time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_data, load_len])
	if TCP in pkt[0] and tcp_flags == "SA" and dst_ip == my_ip:
		tcp_synack_activities.append([pkt[0].time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_data, load_len])

n = 10

interface = conf.iface
my_ip = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3]==interface][0]
my_mac = get_if_hwaddr(interface)
for x in conf.route.routes:
	if x[3]==interface and x[4]==my_ip and x[2]=='0.0.0.0' and IPv4Address(x[1]).compressed.startswith("255.") and IPv4Address(x[0]).compressed.startswith(my_ip.split(".")[0]) and IPv4Address(x[0]).compressed.endswith(".0"):
		netmask = IPv4Address(x[1]).compressed

print("[+] Starting sniffing module.. [For {} seconds]".format(n))
print("[+] Started sniffing module at {}\n".format(str(datetime.now()).split(".")[0]))
start = time.time()
while True:
	try:
		sniff(count=1, prn=analyze)
		assert time.time() - start < n
	except AssertionError:
		sys.exit("[i] Time's up. Thank you !!")
	except:
		sys.exit("[-] There was some unknown error. Shutting Down.")