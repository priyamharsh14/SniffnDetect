import os
import sys
import ctypes
import threading
from scapy.all import *
from ipaddress import *
from queue import Queue
from datetime import datetime

banner = '''-----------------------
SniffnDetect v.1.1
-----------------------
'''

def clear_screen():
	if "linux" in sys.platform:
		os.system("clear")
	elif "win32" in sys.platform:
		os.system("cls")
	else:
		pass

def sniffer_threader():
	while True:
		pkt = sniff(count=1)
		with threading.Lock():
			PACKETS_QUEUE.put(pkt[0])

def analyze_threader():
	while True:
		pkt = PACKETS_QUEUE.get()
		analyze_packet(pkt)
		PACKETS_QUEUE.task_done()

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
	global mac_table, recent_activities, filtered_activities, PACKETS_QUEUE, INTERFACE, MY_NETMASK, MY_IP, MY_MAC
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
		
def analyze_packet(pkt):
	global mac_table, recent_activities, filtered_activities, PACKETS_QUEUE, INTERFACE, MY_NETMASK, MY_IP, MY_MAC
	src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, tcp_flags, icmp_type, load_len = None, None, None, None, None, None, None, None, None
	protocol = []

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
		if src_ip == MY_IP and src_mac != MY_MAC:
			filtered_activities['ICMP-SMURF']['activities'].append([pkt.time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_len])
			recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<ICMP SMURF PACKET>"])
		if load_len>1024:
			filtered_activities['ICMP-POD']['activities'].append([pkt.time, icmp_type, src_ip, src_mac, dst_ip, dst_mac, load_len])
			recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<PING OF DEATH PACKET>"])
	if dst_ip == MY_IP:
		if TCP in pkt:
			if tcp_flags == "S":
				filtered_activities['TCP-SYN']['activities'].append([pkt.time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_len])
				recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<SYN PACKET>"])
			elif tcp_flags == "SA":
				filtered_activities['TCP-SYNACK']['activities'].append([pkt.time, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac, load_len])
				recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, "<SYN-ACK PACKET>"])
	recent_activities.append([pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, None])

def main():
	global mac_table, recent_activities, filtered_activities, PACKETS_QUEUE, INTERFACE, MY_NETMASK, MY_IP, MY_MAC
	sniff_thread = threading.Thread(target=sniffer_threader)
	sniff_thread.daemon = True
	sniff_thread.start()
	analyze_thread = threading.Thread(target=analyze_threader)
	analyze_thread.daemon = True
	analyze_thread.start()
	while True:
		global mac_table, recent_activities, filtered_activities, PACKETS_QUEUE, INTERFACE, MY_NETMASK, MY_IP, MY_MAC
		clear_screen()
		print(banner)
		print('''[i] Current Interface = {}
[i] Current IP = {}
[i] Current Subnet Mask = {}
[i] Current MAC = {}

[i] Recent Activities:
'''.format(INTERFACE, MY_IP, MY_NETMASK, MY_MAC))
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
[i] ICMP Smurf Attack:\t {}
[i] Ping of Death:\t {}
[i] TCP SYN Flood:\t {}
[i] TCP SYN-ACK Flood:\t {}
'''.format(
		filtered_activities['ICMP-SMURF']['flag'], filtered_activities['ICMP-POD']['flag'],
		filtered_activities['TCP-SYN']['flag'], filtered_activities['TCP-SYNACK']['flag'],
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
		time.sleep(0.5)

if __name__=="__main__":
	mac_table = {}
	recent_activities = []
	filtered_activities = {
		'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
		'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
		'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
		'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
	}

	PACKETS_QUEUE = Queue()

	clear_screen()
	if not is_admin():
		print("[-] Please execute the script with root or administrator priviledges.")
		sys.exit(" Exiting.")
	
	INTERFACE = conf.iface
	MY_IP = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3]==INTERFACE][0]
	MY_MAC = get_if_hwaddr(INTERFACE)
	MY_NETMASK = [IPv4Address(x[1]).compressed for x in conf.route.routes if x[3]==INTERFACE and x[4]==MY_IP and x[2]=='0.0.0.0' and IPv4Address(x[1]).compressed.startswith("255.") and IPv4Address(x[0]).compressed.startswith(MY_IP.split(".")[0]) and IPv4Address(x[0]).compressed.endswith(".0")][0]

	try:
		print("[+] Starting sniffing module at {}\n".format(str(datetime.now()).split(".")[0]))
		main()
	except KeyboardInterrupt:
		print("\n[-] Ctrl+C triggered.")
	except EOFError:
		print("\n[-] Ctrl+Z triggered.")
	except:
		print("[-] Some unknown error occured.")
		print("[!] EXCEPTION: "+traceback.print_exc())
	finally:
		sys.exit("\n[-] Exiting.")