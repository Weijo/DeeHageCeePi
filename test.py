#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys, argparse
import threading
from scapy.all import *
import re, functools

conf.checkIPaddr = False
interface = "lo"
start_ip = "192.168.1.100"
end_ip = "192.168.1.200"
netmask = "255.255.255.0"

def checkArgs():
	global interface, start_ip, end_ip, netmask

	parser = argparse.ArgumentParser()
	parser.add_argument("interface", help="interface to sniff")
	parser.add_argument("start", help="DHCP start IP")
	parser.add_argument("end", help="DHCP end IP")
	parser.add_argument("netmask", help="DHCP netmask")
	args = parser.parse_args()
	interface = args.interface
	start_ip = args.start
	end_ip = args.end
	netmask = args.netmask

	if dhcp_server.ip2int("", start_ip) > dhcp_server.ip2int("", end_ip):
		print("err: start ip is larger than end ip")
		sys.exit(2)

class dhcp_server(threading.Thread):
	def __init__(self, **kargs):
		threading.Thread.__init__(self)
		self.filter="udp and src port 68 and dst port 67"
		
		self.parse_args(**kargs)
		self.pool_init()

		self.leases = {}
		self.polllist = []

		self.myIP = get_if_addr(interface)
		self.myMAC = get_if_hwaddr(interface)
		self.broadcast = ltoa(atol(self.myIP) | (0xffffffff & ~atol(self.netmask)))
		self.lease_time = 3600
		self.renewal_time = self.lease_time / 2


	def parse_args(self, **kargs):
		for key, value in kargs.items():
			setattr(self, key, value)

	def pool_init(self):
		self.startIp=self.ip2int(self.start_sip)
		self.endIp=self.ip2int(self.start_eip)

	def poolfree(self, mac):
		"""
		Retrieves an IP from pool of IP, 
		if no IP is available, return 0.0.0.0
		"""
		if mac in self.macip_dict.keys():
			return self.macip_dict[mac]
		else:
			for i in range(self.startIp, self.endIp+1):
				current_ip = self.num2ip(i)
				if current_ip not in self.polllist:
					return current_ip
		return "0.0.0.0"

	def run(self):
		print("running DHCP server on %s:%s\n", self.myMAC, self.myIP)
		print("sniffing...")
		sniff(filter=self.filter,prn=self.detect_parserDhcp,store=0,iface=self.iface)

	def detect_parserDhcp(self, pkt):
		"""
		receives pkt and checks if it is a DHCP packet.
		
		Message Types:
		1->Discover 2->OFFER  3->Request 4->Decline 5->ACK  6->NAK  7->Release 8->Inform
		"""
		if DHCP in pkt:
			Mtype = pkt[DHCP].options[0][1]

			if Mtype == 1 or Mtype == 3:
				your_ip = self.poolfree(pkt[Ether].src)

				repb = pkt.getlayer(BOOTP).copy()
				repb.op = "BOOTREPLY"
				repb.yiaddr = ip

				del(repb.payload)
       			raw = 	Ether(src=self.myMAC, dst=pkt[Ether].src)/
       					IP(src=self.myIP, dst="255.255.255.0") /
       					UDP(sport=req.dport, dport=req.sport) / repb  # noqa: E501
				
				dhcp_options = [(op[0], {1: 2, 3: 5}.get(op[1], op[1])) for op in pkt[DHCP].options if isinstance(op, tuple) and op[0] == "message-type"]

				dhcp_options += [("server_id", self.myIP),
								 ("router", self.myIP),
								 ("name_server", self.myIP),
								 ("broadcast_address", self.broadcast),
								 ("subnet_mask", self.netmask),
								 ("renewal_time", self.renewal_time),
								 ("lease_time", self.lease_time),
								 "end"
								 ]
				raw /= DHCP(options=dhcp_options)

				sendp(raw, iface=self.iface)


	def ip2int(self,ip):
		return functools.reduce(lambda a,b: a<<8 | b, map(int, ip.split(".")))

	def num2ip(self,ip_num):
		return ".".join(map(lambda n: str(ip_num>>n & 0xFF), [24,16,8,0]))

if __name__ == "__main__":
	checkArgs()

	kargs = {
		"iface": interface,
		"netmask": netmask, 
		"start_sip": start_ip,
		"start_eip": end_ip,
	}

	t=dhcp_server(**kargs)
	t.start()