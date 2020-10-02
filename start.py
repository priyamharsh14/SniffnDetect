import os
import sys
import ctypes
from datetime import datetime
from scapy.all import *
from ipaddress import *

mac_table = {}
recent_activities = []
filtered_activities = {
	'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
	'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
	'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
	'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
}
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
		msg.append("["+str(mac_table[mac])+" ("+mac+")]" if mac in mac_table else "[Unknown IP ("+mac+")]")
	return " ".join(msg)

def check_avg_time(activities):
	time = 0
	c = -1
	while c>-21:
		time += activities[c][0] - activities[c-1][0]
		c -= 1
	time /= len(activities)
	return ( time<2 and recent_activities[-1][0] - activities[-1][0] < 10)

def set_flags():
	global filtered_activities, recent_activities
	for category in filtered_activities:
		if len(filtered_activities[category]['activities'])>20:
			filtered_activities[category]['flag'] = check_avg_time(filtered_activities[category]['activities'])
			if filtered_activities[category]['flag']:
				filtered_activities[category]['attacker-mac'] = list(set([i[3] for i in filtered_activities[category]['activities']]))
	
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
	global mac_table, recent_activities, filtered_activities
	clear_screen()
	print(banner)
	print('''[i] Current Interface = {}
[i] Current IP = {}
[i] Current Subnet Mask = {}
[i] Current MAC = {}
[i] Recent Activities:
'''.format(interface, my_ip, netmask, my_mac))
	for i in recent_activities[::-1]:
		if i[8]:
			msg = ' '.join(i[1])+" "+str(i[2])+":"+str(i[6])+" ("+str(i[4])+") => "+str(i[3])+":"+str(i[7])+" ("+str(i[5])+") ["+str(i[8])+" bytes]"
		else:
			msg = ' '.join(i[1])+" "+str(i[2])+":"+str(i[6])+" ("+str(i[4])+") => "+str(i[3])+":"+str(i[7])+" ("+str(i[5])+")"
		if i[9]:
			print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i[0])), msg, i[9])
		else:
			print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i[0])), msg)
	print('''
[i] ICMP Smurf Attack:\t {} - [{} packet(s)]
[i] Ping of Death:\t {} - [{} packet(s)]
[i] TCP SYN Flood:\t {} - [{} packet(s)]
[i] TCP SYN-ACK Flood:\t {} - [{} packet(s)]
'''.format(
	filtered_activities['ICMP-SMURF']['flag'], len(filtered_activities['ICMP-SMURF']['activities']),
	filtered_activities['ICMP-POD']['flag'], len(filtered_activities['ICMP-POD']['activities']),
	filtered_activities['TCP-SYN']['flag'], len(filtered_activities['TCP-SYN']['activities']),
	filtered_activities['TCP-SYNACK']['flag'], len(filtered_activities['TCP-SYNACK']['activities']),
	))
	if any([filtered_activities[category]['flag'] for category in filtered_activities]):
		print("[i] Potential Attacker(s):\n")
		for category in filtered_activities:
			if category == 'ICMP-POD':
				print("Ping of Death Attacker(s): ", find_attackers(filtered_activities[category]['attacker-mac']))
			elif category == 'ICMP-SMURF':
				print("ICMP Smurf Attacker(s): ", find_attackers(filtered_activities[category]['attacker-mac']))
			elif category == 'TCP-SYNACK':
				print("SYN-ACK Flood Attacker(s): ", find_attackers(filtered_activities[category]['attacker-mac']))
			elif category == 'TCP-SYN':
				print("SYN Flood Attacker(s): ", find_attackers(filtered_activities[category]['attacker-mac']))
		print()

def analyze(pkt):
	global mac_table, recent_activities, filtered_activities
	src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, tcp_flags, icmp_type, load_len = None, None, None, None, None, None, None, None, None
	protocol = []
	pkt=pkt[0]
	if len(recent_activities)>5:
		recent_activities = recent_activities[-5:]
	
	for category in filtered_activities:
		if len(filtered_activities[category]['activities'])>30:
			filtered_activities[category]['activities'] = filtered_activities[category]['activities'][-30:]

	set_flags()

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
		load_len = len(pkt[Raw].load)
	
	if ICMP in pkt:
		if src_ip == my_ip and src_mac != my_mac:
			filtered_activities['ICMP-SMURF']['activities'].append([pkt.time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_len])
			recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<ICMP SMURF PACKET>"])
		if load_len>1024:
			filtered_activities['ICMP-POD']['activities'].append([pkt.time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_len])
			recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<PING OF DEATH PACKET>"])
	if dst_ip == my_ip:
		if TCP in pkt:
			if tcp_flags == "S":
				filtered_activities['TCP-SYN']['activities'].append([pkt.time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_len])
				recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<SYN PACKET>"])
			elif tcp_flags == "SA":
				filtered_activities['TCP-SYNACK']['activities'].append([pkt.time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_len])
				recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<SYN-ACK PACKET>"])
	recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, None])

	display()

#Time in Seconds To Run
n = 60
clear_screen()
if not is_admin():
	print("[-] Please execute the script with Admin or root rights\n[-] Exiting..")
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