#!/usr/bin/python3.8
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
	parser.add_argument("netmask", help="DHCP subnet mask")
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

		# DHCP information
		self.myIP = get_if_addr(interface)
		self.myMAC = get_if_hwaddr(interface)
		self.polllist=[] # Used IP pool
		self.macip_dict={} # Record for previous users
		self.lease_time=3600
		self.renewal_time=self.lease_time/2
		self.rebinding_time = self.lease_time*7/8
		self.offer_timeout=0
		self.ack_timeout=0
		self.default_ttl=mac2str('40')
		self.T1=0
		self.T2=0
		
		self.parser_args(**kargs) # parse keyword arguments
		self.pool_init() # Initialise IP Pool
		self.get_broadcast() # set broadcast ip address

		self.filter="udp and src port 68 and dst port 67"

	def parser_args(self,**kargs):
		for key,value in kargs.items():
			if key == "smac" or key == "dmac":
				value = ":".join(value.split("-"))
		setattr(self,key,value)

	def get_broadcast(self):
		self.broadcast_address = re.sub("\.\d{1,3}", ".255", self.myIP)

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
		sniff(filter=self.filter,prn=self.detect_parserDhcp,store=0,iface=self.iface)

	def detect_parserDhcp(self, pkt):
		"""
		receives pkt and checks if it is a DHCP packet.
		
		Message Types:
		1->Discover 2->OFFER  3->Request 4->Decline 5->ACK  6->NAK  7->Release 8->Inform
		"""
		if DHCP in pkt:
			# Set up base packet
			raw=Ether()/IP()/UDP(sport=67,dport=68)/BOOTP()/DHCP()
			raw[Ether].src, raw[IP].src = self.myMAC, self.myIP
			raw[Ether].dst, raw[IP].dst = pkt[Ether].src, "255.255.255.255"
			raw[BOOTP]= BOOTP(op = 2, # reply
							  xid = pkt[BOOTP].xid,
            				  chaddr= self.mac2bin(pkt[Ether].src),
            				  yiaddr="0.0.0.0")/DHCP()

			DhcpOption=[
				("server_id", self.myIP),
				('lease_time',self.lease_time),
				("router", self.myIP),
				("subnet_mask", self.subnet_mask),
				('renewal_time', self.renewal_time),
				('name_server', self.myIP),
				('rebinding_time', self.rebinding_time),
				("broadcast_address", self.broadcast_address),
				('default_ttl',self.default_ttl)]

			Mtype = pkt[DHCP].options[0][1]

			if Mtype == 0x01 or Mtype == 0x03:
				dhcpsip = pkt[IP].src
				dhcpsmac = pkt[Ether].src
				cli_mac = pkt[Ether].src
				localxid = pkt[BOOTP].xid
				your_ip = self.poolfree(dhcpsmac)
				raw[BOOTP].yiaddr = your_ip

				if your_ip == "0.0.0.0":
					# No more available IP, send NAK
					BootpHeader.yiaddr = your_ip # consider changing
					nak = (Ether(src=self.myMAC, dst="ff:ff:ff:ff:ff:ff")/
						  IP(src=self.myIP, dst="255.255.255.255")/
						  UDP(sport=67,dport=68)/
						  BootpHeader/
						  DHCP(options=[("message-type","nak"),("server_id",self.myIP),"end"]))
					sendp(nak ,verbose=0, iface=self.iface)
                
				else:
					if Mtype == 1:
						# Respond to DISCOVER Packets
						DhcpOption.insert(0, ("message-type","offer"))
						DhcpOption.append("end")
						DhcpOption.append(mac2str("00")*20)
						raw[DHCP]=DHCP(options=DhcpOption)

						print(f"raw.summary={raw.summary}")

						if self.waittimeout(self.offer_timeout):
							sendp(raw, iface=self.iface)

					elif Mtype == 3:
						# Respond to REQUEST Packets
						DhcpOption.insert(0,("message-type","ack"))
						DhcpOption.append("end")
						DhcpOption.append(mac2str("00")*20)
						raw[DHCP]=DHCP(options=DhcpOption)

						if pkt[BOOTP].ciaddr == "0.0.0.0":
							# New client
							if self.waittimeout(self.ack_timeout):
								sendp(raw, verbose=0, iface=self.iface)
								self.macip_dict[dhcpsmac]= your_ip
								self.polllist.append(your_ip)
						else:
							if pkt[IP].src == "0.0.0.0":
								if self.waittimeout(self.T2):
									sendp(raw,verbose=0,iface=self.iface)
									self.macip_dict[dhcpsmac]=your_ip
									self.polllist.append(your_ip)
							else:
								if self.waittimeout(self.T1):
									sendp(raw,iface=self.iface)
									self.macip_dict[dhcpsmac]=your_ip
									self.polllist.append(your_ip)
			elif Mtype == 4:
				# Declined IP due to duplicate IP
				options=pkt[DHCP].options
				optionlen=len(options)
				for i in range(optionlen):
					if options[i][0] == "requested_addr":
						self.polllist.append(options[i][1])
						break

			elif Mtype == 7:
				# Release IP
				dhcpsip = pkt[IP].src
				dhcpsmac = pkt[Ether].src
				self.polllist.remove(dhcpsmac)

	def waittimeout(self, num):
		num=int(num)
		if num>=0:
			time.sleep(num)
			return True
		else:
			return False

	def mac2bin(self,mac,flag=":-"):
		hexlist=re.split(r"[%s]" %(flag),mac)
		hexstr="".join(hexlist)
		binmac=self.hex2bin(hexstr)
		return binmac

	def ip2int(self,ip):
		return functools.reduce(lambda a,b: a<<8 | b, map(int, ip.split(".")))

	def num2ip(self,ip_num):
		return ".".join(map(lambda n: str(ip_num>>n & 0xFF), [24,16,8,0]))

if __name__ == "__main__":
	checkArgs()

	kargs = {
		"iface": interface,
		"subnet_mask": netmask, 
		"start_sip": start_ip,
		"start_eip": end_ip,
	}

	t=DhcpServer(**kargs)
	t.start()