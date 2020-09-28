#!/usr/bin/python

from scapy.all import *
from scapy.layers.http import *

#look at the entire pcap file
def check_pcap(packets):
	packets.summary()

#Look for usernames and passwords
def search_credentials(packets):
	counter = 0
	for pkt in packets:
		counter = counter + 1
		if pkt.haslayer(scapy.all.Raw):		#Checking if the Raw layer is present
			load = pkt[scapy.all.Raw].load		#Load field contains a lot of information like credentials
			keywords = ["login", "password", "username", "user", "pass"]
			for keyword in keywords:
				if bytes(keyword, 'utf-8') in load:
					print("Found a login at packet", counter-1, ": ", load)

#Search the IP source of a packet
def search_IP_src(packets, num_packet):
	print(num_packet, "packet IP source address: ", packets[num_packet][IP].src)

#Search the IP destination of a packet
def search_IP_dst(packets, num_packet):
	print(num_packet, "packet IP destination address: ", packets[num_packet][IP].dst)

#Check packets with TCP or UDP layers
def search_TCP_UDP(packets, choice_TU):
	count = 0
	if (choice_TU == "TCP"):
		for pkt in packets:
			count = count + 1
			if pkt.haslayer(TCP):
				response_sequence_number = pkt[TCP].seq
				response_acknowledgement_number = pkt[TCP].ack
				response_timestamp = pkt[TCP].time
				print("Packet", count-1, "---> Response seq: " + str(response_sequence_number) + " ack: " + str(response_acknowledgement_number) + " timestamp: " + str(response_timestamp))
	if (choice_TU == "UDP"):
		for pkt in packets:
			count = count + 1
			if pkt.haslayer(UDP):
				response_payload = pkt[UDP].payload
				response_timestamp = pkt[UDP].time
				print("Packet", count-1, "---> Payload: " + str(response_payload) + " timestamp: " + str(response_timestamp))
		else:
			print("No packets with TCP/UDP layers")

if __name__ == '__main__':
	packets = rdpcap('C:/example/example.pcap')
	while(1):
		print("\nWELCOME TO PACKET SNIFFER WITH PYTHON!")
		print("---------------------------------------------------\n")
		print("1) Check the entire pcap file\n2) Look for login usernames or passwords\n3) Check the IP source address of a specific packet")
		print("4) Check the IP destination address of a specific packet\n5) Search which packets have a TCP or UDP layer\n6) Exit")
		pick = input("Please pick a number to choose what you want to do: ")
		if (pick == "1"):
			check_pcap(packets)
		elif (pick == "2"):
			search_credentials(packets)
		elif (pick == "3"):
			number_packet_ip_src = input("Write the number of the packet that you want to know its IP source (starting from 0): ")
			num_packet_src = int(number_packet_ip_src)
			search_IP_src(packets, num_packet_src)
		elif (pick == "4"):
			number_packet_ip_dst = input("Write the number of the packet that you want to know its IP destination (starting from 0): ")
			num_packet_dst = int(number_packet_ip_dst)
			search_IP_dst(packets, num_packet_dst)
		elif (pick == "5"):
			TCP_UDP = input("Which layers are you looking for? (TCP or UDP): ")
			search_TCP_UDP(packets, TCP_UDP)
		elif (pick == "6"):
			break
		else:
			print("Please pick a number between 1 and 6")
