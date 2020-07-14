ifconfig eth0 down

sudo rm /etc/network/interfaces -rf
echo 'auto eth0' > /etc/network/interfaces
echo 'iface eth0 inet static' >> /etc/network/interfaces
echo 'address 192.168.3.4' >> /etc/network/interfaces
echo 'netmask 255.255.255.0' >> /etc/network/interfaces
echo 'network 192.168.3.0' >> /etc/network/interfaces
echo 'broadcast 192.168.3.255' >> /etc/network/interfaces
echo 'gateway 192.168.3.1' >> /etc/network/interfaces
echo 'dns-nameservers 192.168.3.1' >> /etc/network/interfaces

sudo rm /etc/resolve.conf -rf
sudo /etc/init.d/networking restart
