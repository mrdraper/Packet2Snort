try:
	from scapy.all import *
except ImportError:
	sys.stderr.write("ERROR: You must have scapy installed.\n")
	sys.stderr.write("You can install it by running: sudo pip install -U 'scapy>=2.3,<2.4'")
	exit(1)
try:
	from scapy.layers import http
except ImportError:
	sys.stderr.write("ERROR: You must have scapy-http installed.\n")
	sys.stderr.write("You can install it by running: sudo pip install -U 'scapy>=1.8'")
	exit(1)
    
import getopt
import sys

def usage():
	print "----\/---- Packet2Snort ----\/----"
	print "\nThis script parses a network packet from a PCAP file into a useable Snort rule for incident response, threat hunting and detection."
	print "\nRequirements: \n- Scapy \n- Scapy-HTTP \n- Python 2.7"
	print "\nUsage:\npacket2snort.py <options>\n"
	print "Arguments: \n"
	print "-r <pcap> input pcap file"
	print "-p <packetnr> input packet number in pcap"
	print "-s to output snort rule from single packet"
	sys.exit(0)

#converts layer 3 and 4 protocols into rules:
# IP, TCP, UDP & ICMP
def basicconvert(singlepacket, packetnr0):
	try:
		print ("\n{1}----- Snort Rules For Packet Number {0}-----{2}".format(packetnr0, G, W))
# Print IP Layer Rules
# Check if the IP layer is present in the packet
		if IP in singlepacket:
			print ("{0}----- Layer 3/4 Rules -------{1}".format(G, W))
			ipsource = singlepacket[IP].src
			ipdest = singlepacket[IP].dst
# Print TCP Layer Rules
# Check if TCP is present in the packet
			if TCP in singlepacket:
				print ("{0}----- TCP ---\n{1}".format(G, W))
				tcpsourceport = singlepacket[TCP].sport
				tcpdestport = singlepacket[TCP].dport
				print ("alert tcp {0} {1}-> $HOME_NET any (msg: \"Suspicious IP {0} and port {1} detected!\"; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)".format(tcpsourceport, tcpdestport))
				print ("alert tcp $HOME_NET any -> {0} {1} (msg: \"Suspicious IP {0} and port {1} detected!\"; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)".format(ipdest, tcpdestport))
# Check if DNS is present in the packet				
				if DNS in singlepacket:
					print ("{0}----- DNS ---\n{1}".format(G, W))
					hostname = singlepacket[DNSQR].qname
					if DNSRR in singlepacket:
						hostaddr = singlepacket[DNSRR].rdata	
						print ("alert udp any 53 -> $HOME_NET any (msg: \"Suspicious DNS reply for {0} with address {1} detected!\"; content:\"|00 01 00 01|\"; content:\"|00 04".format(hostname, hostaddr)),
						addrsplit = hostaddr.split('.')
						for addr in addrsplit:
							hexaddr = format(int(addr), '02x')
							print "\b",hexaddr.upper(),
						print "\b|\"; distance:4; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)"
					else:
						print ("alert udp $HOME_NET any -> any 53 (msg: \"Suspicious DNS request for {0} detected!\"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth:10; offset:2; content:\"".format(hostname)),
						dnsplit = hostname.split('.')
						for word in dnsplit:
							if word != '':
								numbers = len(word)
								hexa = format(numbers, '02x')
								upper = hexa.upper()
								print ("\b|{0}|{1}".format(upper, word)),
						print "\b\"; fast_pattern; nocase; distance:0; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)"				
# Check if a HTTP request is present in the packet				
				elif singlepacket.haslayer(http.HTTPRequest):
					print ("\n{0}----- Layer 7 Rules -----{1}".format(G, W))
					print ("{0}----- HTTP -----\n{1}".format(G, W))
					httppacket = singlepacket.getlayer(http.HTTPRequest)
					print ("Host:\nalert tcp $HOME_NET any -> any $HTTP_PORTS (msg: \"Suspicious HTTP {0[Method]} request to {0[Host]} detected!\"; flow:established,to_server; content:\"Host|3a 20|{0[Host]}|0d 0a|\"; http_header; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)".format(httppacket.fields))
					print ("\nFilename:\nalert tcp $HOME_NET any -> any $HTTP_PORTS (msg: \"Suspicious HTTP file name \"{0[Path]}\" requested at {0[Host]}!\"; flow:established,to_server; content:\"{0[Path]}\"; http_uri; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)".format(httppacket.fields))
# Check if a HTTP response is present in the packet	(Currently not active)			
#				elif singlepacket.haslayer(http.HTTPResponse):
#					print "\n------ Layer 7 Rules ------"
#					print "\n--- HTTP ---\n"
#					httppacket2 = singlepacket.getlayer(http.HTTPResponse)
#					print httppacket2
# Print UDP Layer Rules
# Check if UDP is present in the packet
			elif UDP in singlepacket:
				print ("{0}----- UDP -----\n{1}".format(G, W))
				udpsrcport = singlepacket[UDP].sport
				udpdestport = singlepacket[UDP].dport
				print ("alert udp {0} {1} -> any any (msg: \"Suspicious IP {0} and port {1} detected!\"; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)".format(ipsource, udpsrcport))
				print ("alert udp any any -> {0} {1} (msg: \"Suspicious IP {0} and port {1} detected!\"; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)".format(ipdest, udpdestport))
# Check if DNS is present in the packet				
				if DNS in singlepacket:
					print ("{0}----- DNS -----\n{1}".format(G, W))
					hostname = singlepacket[DNSQR].qname
					if DNSRR in singlepacket:
						hostaddr = singlepacket[DNSRR].rdata	
						print ("alert udp any 53 -> $HOME_NET any (msg: \"Suspicious DNS reply for {0} with address {1} detected!\"; content:\"|00 01 00 01|\"; content:\"|00 04".format(hostname, hostaddr)),
						addrsplit = hostaddr.split('.')
						for addr in addrsplit:
							hexaddr = format(int(addr), '02x')
							print "\b",hexaddr.upper(),
						print "\b|\"; distance:4; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)"
					else:
						print ("alert udp $HOME_NET any -> any 53 (msg: \"Suspicious DNS request for {0} detected!\"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth:10; offset:2; content:\"".format(hostname)),
						dnsplit = hostname.split('.')
						for word in dnsplit:
							if word != '':
								numbers = len(word)
								hexa = format(numbers, '02x')
								upper = hexa.upper()
								print ("\b|{0}|{1}".format(upper, word)),
						print "\b|00|\"; fast_pattern; nocase; distance:0; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)"				
# Print ICMP Layer Rules
# Check if ICMP is present in the packet
			elif ICMP in singlepacket:
				print ("{0}----- ICMP -----\n{1}".format(G, W))
				icmptype = singlepacket[ICMP].type
				print ("alert icmp {0} any -> {1} any (msg: \"Suspicious ICMP packet from {0} to {1} with type {2}!\"; icode:0; itype:{2}; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)".format(ipsource, ipdest, icmptype))
# Throw error when no L4 protocols found
			else:
				print ("{0}No UDP/TCP Layer 4 Protocol Found!{1}".format(O, W))
				sys.exit(1)
# Throw error when no IP found
		else:
			print ("{0}No IP Layer 3 Protocol Found!{1}".format(O, W))
			sys.exit(1)
		print ("\n{0}Don't forget to change the sid of the generated rule(s)!{1}".format(O, W))
# Print error when they occur	
	except Exception, e:
		print "Error: ", e
		print "\n"
		usage()
		pass

#Let user input pcap
def main():
	try:
#Let user input pcap
		cap = None
		packetnr = None
		protocol = None
		snortoutput = False
		options, arguments = getopt.getopt(sys.argv[1:], "r:p:P:sh")

#Check if argument is given and fill variables with arguments
		if len(sys.argv) == 1:
			usage()

		for opt, args in options:
			if opt in ('-r'):
				cap = args
			elif opt in ('-p'):
				packetnr = args.split(',')
			elif opt in ('-h'):
				usage()
			elif opt in ('-s'):
				snortoutput = True
			else:
				print "No arguments given"
				sys.exit(1)

# Check if pcap file exists
		if cap:
			if os.path.isfile(cap):
				scapy_cap = rdpcap(cap)
			else:
				print "Error:", cap, "doest not exist."
				sys.exit(1)
		
#Output summary of pcap
		print (O + "--------")
		print "Summary: " + str(scapy_cap)
		print ("--------" + W)
# Check if a packet number has been supplied, and thus the variable packetnr is filled
		if packetnr != None:
			for i in packetnr:
				packetnr0 = int(i) - 1
				singlepacket = scapy_cap[int(packetnr0)]
# Check if the -s paramater is give, and thus the script needs to output Snort.
				if snortoutput == True:
					basicconvert(singlepacket, packetnr0)
# If the -s paramater is not give, just output the details of the packet selected.
				else:
					print str(singlepacket.show())
# Check if the pcap file is given
		elif cap != None:
			countpacket = 1
			for packet in scapy_cap:
# Print a summary of each packet in the pcap, together with a packetnumber				
				print str(countpacket), packet.summary()
# Add a count to the packetnumber				
				countpacket = countpacket + 1
# When no argument is give, return the useage function		
		else:
			useage()
# Print out the error, if received
	except Exception, e:
		print "Error: ", e
		print "\n"
		usage()
		pass

G = '\033[32m'
W = '\033[0m'
O = '\033[33m'
if __name__ == '__main__':
	main()
