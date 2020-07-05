# DHCPspoof

DHCP server spoof using Scapy.
Only works on local subnet, if server is set up on another subnet it will not work.

Tested on python 2
```
python DHCPspoof.py <interface> <starting ip> <ending ip> <subnet mask> [options]

eg. python DHCPspoof.py eth0 192.168.1.100 192.168.1.200 255.255.255.0 -s
```

#### Options
- s ---> DHCPserver will flood the network with DHCP DISCOVER packets to deplete existing dhcp server's pool of ip addresses before switching on DHCP server.