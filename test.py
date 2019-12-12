import os
import sys
import datetime
from scapy.all import *
from ipaddress import *

def clear_screen():
	if "linux" in sys.platform:
		os.system("clear")
	elif "win32" in sys.platform:
		os.system("cls")
	else:
		pass

def display():
	global mac_table, recent_activities, tcp_syn_activities, icmp_pod_activities, icmp_smurf_activities, tcp_synack_activities
	global icmp_smurf_flag, icmp_pod_flag, syn_flood_flag, synack_flood_flag
	clear_screen()
	print(banner)
	print("[+] Current Interface =",interface)
	print("[+] Current IP =",my_ip)
	print("[+] Current Subnet Mask =",netmask)
	print("[+] Current MAC = {}\n".format(my_mac))
	print("[+] Recent Activities:\n")
	for i in recent_activities[::-1]:
		if i[8]:
			msg = ' '.join(i[1])+" "+str(i[2])+":"+str(i[6])+" ("+str(i[4])+") => "+str(i[3])+":"+str(i[7])+" ("+str(i[5])+") ["+str(i[8])+" bytes]"
		else:
			msg = ' '.join(i[1])+" "+str(i[2])+":"+str(i[6])+" ("+str(i[4])+") => "+str(i[3])+":"+str(i[7])+" ("+str(i[5])+")"
		if i[9]:
			print(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(i[0])), msg, i[9])
		else:
			print(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(i[0])), msg)
	print("\n[+] ICMP Smurf Attack:\t {} - [{} packet(s)]".format(icmp_smurf_flag[0], len(icmp_smurf_activities)))
	print("[+] Ping of Death:\t {} - [{} packet(s)]".format(icmp_pod_flag[0], len(icmp_pod_activities)))
	print("[+] TCP SYN Flood:\t {} - [{} packet(s)]".format(syn_flood_flag[0], len(tcp_syn_activities)))
	print("[+] TCP SYN-ACK Flood:\t {} - [{} packet(s)]".format(synack_flood_flag[0], len(tcp_synack_activities)))

def analyze(pkt):
	global mac_table, recent_activities, tcp_syn_activities, icmp_pod_activities, icmp_smurf_activities, tcp_synack_activities
	global icmp_smurf_flag, icmp_pod_flag, syn_flood_flag, synack_flood_flag
	src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, tcp_flags, icmp_type, load_len = None, None, None, None, None, None, None, None, None
	protocol = []
	
	if len(recent_activities)>5:
		recent_activities = recent_activities[-5:]

	if len(tcp_syn_activities)>2:
		syn_flood_flag[0] = True

	if len(tcp_synack_activities)>2:
		synack_flood_flag[0] = True

	if len(icmp_pod_activities)>2:
		icmp_pod_flag[0] = True

	if len(icmp_smurf_activities)>2:
		icmp_smurf_flag[0] = True

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
		tcp_flags = pkt[0][TCP].flags.flagrepr()
	
	if UDP in pkt[0]:
		protocol.append("UDP")
		src_port = pkt[0][UDP].sport
		dst_port = pkt[0][UDP].dport
	
	if ICMP in pkt[0]:
		protocol.append("ICMP")
		icmp_type = pkt[0][ICMP].type # 8 for echo-request and 0 for echo-reply
	
	if ARP in pkt[0] and pkt[0][ARP].op in (1,2):
		protocol.append("ARP")
		if pkt[0][ARP].hwsrc not in mac_table.keys():
			mac_table[pkt[0][ARP].hwsrc] = pkt[0][ARP].psrc

	if Raw in pkt[0]:
#		load_data = pkt[0][Raw].load
		load_len = len(pkt[0][Raw].load)

	if src_ip == my_ip and src_mac != my_mac and ICMP in pkt[0]:
		icmp_smurf_activities.append([pkt[0].time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_len])
		recent_activities.append([pkt[0].time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<ICMP SMURF PACKET>"])
	if ICMP in pkt[0] and load_len>65535:
		icmp_pod_activities.append([pkt[0].time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_len])
		recent_activities.append([pkt[0].time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<PING OF DEATH PACKET>"])
	if TCP in pkt[0] and tcp_flags == "S" and dst_ip == my_ip:
		tcp_syn_activities.append([pkt[0].time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_len])
		recent_activities.append([pkt[0].time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<SYN PACKET>"])
	if TCP in pkt[0] and tcp_flags == "SA" and dst_ip == my_ip:
		tcp_synack_activities.append([pkt[0].time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_len])
		recent_activities.append([pkt[0].time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<SYN-ACK PACKET>"])
	recent_activities.append([pkt[0].time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, None])

	display()

mac_table = {}
recent_activities = []
tcp_syn_activities = []
tcp_synack_activities = []
icmp_pod_activities = []
icmp_smurf_activities = []
icmp_pod_flag = [False, None]
icmp_smurf_flag = [False, None]
syn_flood_flag = [False, None]
synack_flood_flag = [False, None]
banner = '''
-----------------------
SniffnDetect v.1.0alpha
-----------------------
'''

n = 10

interface = conf.iface
my_ip = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3]==interface][0]
my_mac = get_if_hwaddr(interface)
for x in conf.route.routes:
	if x[3]==interface and x[4]==my_ip and x[2]=='0.0.0.0' and IPv4Address(x[1]).compressed.startswith("255.") and IPv4Address(x[0]).compressed.startswith(my_ip.split(".")[0]) and IPv4Address(x[0]).compressed.endswith(".0"):
		netmask = IPv4Address(x[1]).compressed

print("[+] Starting sniffing module..")
print("[+] Started sniffing module at {}\n".format(str(datetime.now()).split(".")[0]))
start = time.time()
while True:
	try:
		assert time.time() - start < n
		sniff(count=1, prn=analyze)
	except AssertionError:
		sys.exit("\n[i] Time's up. Thank you !!")
#	except:
#		sys.exit("[-] There was some unknown error. Shutting Down.")