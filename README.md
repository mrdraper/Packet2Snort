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
- Basic IP/TCP(/UDP)
- ICMP From -> To + Type
- HTTP Hostname
- HTTP Filename
- DNS Query
- DNS Reply


### Example

1. Once we have analyzed a pcap file and determined that some packets are malicious and should be triggered upon by our Snort IDS, we can use this script to automatically generate rules from this known malicious packet. Let's say, we found this packet of a DNS Query and want our Snort setup to trigger on it, we thus need to create a rule.

1	Standard query 0x429b A ow83yu4gtopw3u.win	0.000000	10.8.29.102	10.8.27.1	DNS	78

2. We need to know the packet number (easily spotted in a tool like WireShark). Alternatively, you can read the pcap with the -r switch and determine the packet number from there, since the script automatically outputs packetnumbers in this mode, for example:
```
$ python packet2snort.py -r malware.pcap

--------
Summary: <malware.pcap: TCP:2273 UDP:2 ICMP:0 Other:0>
--------
1 Ether / IP / UDP / DNS Qry "ow83yu4gtopw3u.win." 
2 Ether / IP / UDP / DNS Ans "119.28.47.202" 
3 Ether / IP / TCP 10.8.29.102:49165 > 119.28.47.202:https S
4 Ether / IP / TCP 119.28.47.202:https > 10.8.29.102:49165 SA / Padding
```
3. Once we know the packet number, use the switch -p with the correct packet number (read point 2) to display the packet.
```
python packet2snort.py -r malware.pcap -p 1

--------
Summary: <malware.pcap: TCP:2273 UDP:2 ICMP:0 Other:0>
--------
###[ Ethernet ]### 
  dst       = 20:e5:2a:b6:93:f1
  src       = 00:08:02:1c:47:ae
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 64
     id        = 966
     flags     = 
     frag      = 0
     ttl       = 128
     proto     = udp
     chksum    = 0xea70
     src       = 10.8.29.102
     dst       = 10.8.27.1
     \options   \
###[ UDP ]### 
        sport     = 54230
        dport     = domain
        len       = 44
        chksum    = 0xc49a
###[ DNS ]### 
           id        = 17051
           qr        = 0
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 0
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]### 
            |  qname     = 'ow83yu4gtopw3u.win.'
            |  qtype     = A
            |  qclass    = IN
           an        = None
           ns        = None
           ar        = None
```

4. Next, use the -s switch to generate snort rules from this packet. (Don't forget to change the sid to the number right for your environment.) We can see the following output:
```
$ python packet2snort.py -r malware.pcap -p 1 -s
 ----- Snort Rules ----- 

------ Layer 3/4 Rules -------

--- UDP ---

alert udp 10.8.29.102 54230 -> any any (msg: "Suspicious IP 10.8.29.102 and port 54230 detected!"; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)
alert udp any any -> 10.8.27.1 53 (msg: "Suspicious IP 10.8.27.1 and port 53 detected!"; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)

--- DNS ---

alert udp $HOME_NET any -> any 53 (msg: "Suspicious DNS request for ow83yu4gtopw3u.win. detected!"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|0E|ow83yu4gtopw3u|03|win|00|"; fast_pattern; nocase; distance:0; reference:Packet2Snort; classtype:trojan-activity; sid:xxxx; rev:1;)
```
5. Test, and then implement the rule(s) you want that have been generated. Win!

### Known issues
Some issues I encountered along the way:
- Install scapy from source: https://github.com/secdev/scapy. When i installed from pip, my layers files were not up to date, thus i could not see DNS in TCP for example.

### TO DO
This script was just an experiment with Snort, Python and Scapy. The following are some things i want to add in the future:
- HTTPS support
	- SSL Certs, etc.
~~- Support for multiple packet conversions (or entire pcaps)~~
- SMB support
- More advanced ruling on IP/TCP layer (Offset, checksum, etc.)
- ...

Feel free to submit pull requests or just leave some feedback. 

