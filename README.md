# Packet2Snort

This python script automatically generates a standard set of Snort IDS rules from a network packet out of a .pcap file.

## Requirements

- Python 2.7
- scapy 
- scapy-http
- a valid .pcap file

### Usage

----\/---- Packet2Snort ----\/----

This script parses a network packet from a PCAP file into a useable Snort rule for incident response, threat hunting and detection.

Usage:
packet2snort.py <options>

Arguments: 

-r <pcap> input pcap file
-p <packetnr> input packet number in pcap
-s to output snort rule from single packet

### Output

Currently, this script automatically outputs the following rules from a packet:
- Basic IP/TCP(UDP)
- ICMP From -> To + Type
- HTTP Hostname
- HTTP Filename
- DNS Query
- DNS Reply


### Example

1. Once we have analyzed a pcap file and determined that some packets are malicious and should be triggered upon by our Snort IDS, we can use this script to automatically generate rules from this known malicious packet.

2. We need to know the packet number (easily spotted in a tool like WireShark). For this script, enter the packet number from WireShark -1, since WireShark starts counting at 1 and this script at 0. (Will try to fix later on). Alternatively, you can read the pcap with the -r switch and determine the packet number from there.

3. Once we know the packet number, use the switch -p with the correct packet number (read point 2) to display the packet.

4. Next, use the -s switch to generate snort rules from this packet. (Don't forget to change the sid to the number right for your environment.)

5. Test, and then implement the rule(s) you want that have been generated. Win!

### Known issues
Some issues I encountered along the way:
- Install scapy from source: https://github.com/secdev/scapy. When i installed from pip, my layers files were not up to date, thus i could not see DNS in TCP for example.

### TO DO
This script was just an experiment with Snort, Python and Scapy. The following are some things i want to add in the future:
- HTTPS support
	- SSL Certs, etc.
- Support for multiple packet conversions (or entire pcaps)
- SMB support
- More advanced ruling on IP/TCP layer (Offset, checksum, etc.)
- ...

Feel free to submit pull requests or just leave some feedback. 

