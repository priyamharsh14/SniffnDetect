import os
import sys
import ctypes
from datetime import datetime
from scapy.all import *
from ipaddress import *

mac_table = {}
recent_activities = []
tcp_syn_activities = []
tcp_synack_activities = []
icmp_pod_activities = []
icmp_smurf_activities = []
icmp_pod_flag = [False, []]
icmp_smurf_flag = [False, []]
syn_flood_flag = [False, []]
synack_flood_flag = [False, []]
banner = '''-----------------------
SniffnDetect v.1.0beta
-----------------------
'''

def clear_screen():
	if "linux" in sys.platform:
		os.system("clear")
	elif "win32" in sys.platform:
		os.system("cls")
	else:
		pass

def find_attackers(mac_data):
	msg = []
	for mac in mac_data:
		if mac in mac_table.keys():
			msg.append("["+str(mac_table[mac])+" ("+mac+")]")
		else:
			msg.append("[Unknown IP ("+mac+")]")
	return " ".join(msg)

def check_avg_time(activities):
	time = []
	for i in range(len(activities)-1,len(activities)-21,-1):
		time.append(activities[i][0]-activities[i-1][0])
	time = sum(time)/len(activities)
	return ( time<2 and recent_activities[-1][0] - activities[-1][0]<5)

def set_flag(activities):
	temp_flag = [False,None]
	if len(activities)>20:
		temp_flag[0] = check_avg_time(activities)
		if temp_flag[0]:
			temp_flag[1] = list(set([i[3] for i in activities]))
	return temp_flag
	
def is_admin():
	try:
		return os.getuid() == 0
	except AttributeError:
		pass
	try:
		return ctypes.windll.shell32.IsUserAnAdmin() == 1
	except AttributeError:
		return False
def display():
	global mac_table, recent_activities, tcp_syn_activities, icmp_pod_activities, icmp_smurf_activities, tcp_synack_activities
	global icmp_smurf_flag, icmp_pod_flag, syn_flood_flag, synack_flood_flag
	clear_screen()
	print(banner)
	print("[i] Current Interface =",interface)
	print("[i] Current IP =",my_ip)
	print("[i] Current Subnet Mask =",netmask)
	print("[i] Current MAC = {}\n".format(my_mac))
	print("[i] Recent Activities:\n")
	for i in recent_activities[::-1]:
		if i[8]:
			msg = ' '.join(i[1])+" "+str(i[2])+":"+str(i[6])+" ("+str(i[4])+") => "+str(i[3])+":"+str(i[7])+" ("+str(i[5])+") ["+str(i[8])+" bytes]"
		else:
			msg = ' '.join(i[1])+" "+str(i[2])+":"+str(i[6])+" ("+str(i[4])+") => "+str(i[3])+":"+str(i[7])+" ("+str(i[5])+")"
		if i[9]:
			print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i[0])), msg, i[9])
		else:
			print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i[0])), msg)
	print("\n[i] ICMP Smurf Attack:\t {} - [{} packet(s)]".format(icmp_smurf_flag[0], len(icmp_smurf_activities)))
	print("[i] Ping of Death:\t {} - [{} packet(s)]".format(icmp_pod_flag[0], len(icmp_pod_activities)))
	print("[i] TCP SYN Flood:\t {} - [{} packet(s)]".format(syn_flood_flag[0], len(tcp_syn_activities)))
	print("[i] TCP SYN-ACK Flood:\t {} - [{} packet(s)]\n".format(synack_flood_flag[0], len(tcp_synack_activities)))
	if any([icmp_pod_flag[0], icmp_smurf_flag[0], synack_flood_flag[0], syn_flood_flag[0]]):
		print("[i] Potential Attacker(s):\n")
		for i in enumerate([icmp_pod_flag, icmp_smurf_flag, synack_flood_flag, syn_flood_flag]):
			if i[1][0]:
				if i[0] == 0:
					print("Ping of Death Attacker(s): ", find_attackers(i[1][1]))
				elif i[0] == 1:
					print("ICMP Smurf Attacker(s): ", find_attackers(i[1][1]))
				elif i[0] == 2:
					print("SYN-ACK Flood Attacker(s): ", find_attackers(i[1][1]))
				elif i[0] == 3:
					print("SYN Flood Attacker(s): ", find_attackers(i[1][1]))
		print()

def analyze(pkt):
	global mac_table, recent_activities, tcp_syn_activities, icmp_pod_activities, icmp_smurf_activities, tcp_synack_activities
	global icmp_smurf_flag, icmp_pod_flag, syn_flood_flag, synack_flood_flag
	src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, tcp_flags, icmp_type, load_len = None, None, None, None, None, None, None, None, None
	protocol = []
	pkt=pkt[0]
	if len(recent_activities)>5:
		recent_activities = recent_activities[-5:]

	syn_flood_flag = set_flag(tcp_syn_activities)
	synack_flood_flag = set_flag(tcp_synack_activities)
	icmp_pod_flag = set_flag(icmp_pod_activities)
	icmp_smurf_flag = set_flag(icmp_smurf_activities)

	if Ether in pkt:
		src_mac = pkt[Ether].src
		dst_mac = pkt[Ether].dst
	elif IP in pkt:
		src_ip = pkt[IP].src
		dst_ip = pkt[IP].dst
	
	if TCP in pkt:
		protocol.append("TCP")
		src_port = pkt[TCP].sport
		dst_port = pkt[TCP].dport
		tcp_flags = pkt[TCP].flags.flagrepr()
	elif UDP in pkt:
		protocol.append("UDP")
		src_port = pkt[UDP].sport
		dst_port = pkt[UDP].dport
	elif ICMP in pkt:
		protocol.append("ICMP")
		icmp_type = pkt[ICMP].type # 8 for echo-request and 0 for echo-reply
	
	if ARP in pkt and pkt[ARP].op in (1,2):
		protocol.append("ARP")
		if pkt[ARP].hwsrc in mac_table.keys() and mac_table[pkt[ARP].hwsrc] != pkt[ARP].psrc:
			mac_table[pkt[ARP].hwsrc] = pkt[ARP].psrc
		if pkt[ARP].hwsrc not in mac_table.keys():
			mac_table[pkt[ARP].hwsrc] = pkt[ARP].psrc

	if Raw in pkt:
#		load_data = pkt[Raw].load
		load_len = len(pkt[Raw].load)
	
	if ICMP in pkt:
		if src_ip == my_ip and src_mac != my_mac:
			icmp_smurf_activities.append([pkt.time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_len])
			recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<ICMP SMURF PACKET>"])
		if load_len>1024:
			icmp_pod_activities.append([pkt.time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_len])
			recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<PING OF DEATH PACKET>"])
	if dst_ip == my_ip:
		if TCP in pkt:
			if tcp_flags == "S":
				tcp_syn_activities.append([pkt.time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_len])
				recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<SYN PACKET>"])
			elif tcp_flags == "SA":
				tcp_synack_activities.append([pkt.time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_len])
				recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<SYN-ACK PACKET>"])
	recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, None])

	display()

#Time in Seconds To Run
n = 60
clear_screen()
if not is_admin():
	print("\t\tPlease Execute With Admin or sudo rights\nExiting")
	sys.exit(0)
interface = conf.iface
my_ip = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3]==interface][0]
my_mac = get_if_hwaddr(interface)
for x in conf.route.routes:
	if x[3]==interface and x[4]==my_ip and x[2]=='0.0.0.0' and IPv4Address(x[1]).compressed.startswith("255.") and IPv4Address(x[0]).compressed.startswith(my_ip.split(".")[0]) and IPv4Address(x[0]).compressed.endswith(".0"):
		netmask = IPv4Address(x[1]).compressed

print("[+] Starting sniffing module at {} for {} seconds\n".format(str(datetime.now()).split(".")[0], n))
start = time.time()
while True:
	try:
		assert time.time() - start < n
		sniff(count=1, prn=analyze)
	except AssertionError:
		sys.exit("[i] Time's up. Thank you !!")
#	except:
#		sys.exit("[-] There was some unknown error. Shutting Down.")