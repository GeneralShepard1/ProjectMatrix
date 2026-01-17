#1.1 Provjera IP adrese
ip a

1.2 Ručna konfiguracija mreže (ako nema IP)
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager
sudo ip addr flush dev eth0
sudo ip addr add 172.27.170.100/20 dev eth0
sudo ip route add default via 172.27.160.1
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

1.3 Provjera konekcije
ping -c 2 172.27.160.1
ping -c 2 8.8.8.8
ping -c 2 google.com

1.4 Lokalni portovi na Kali (šta sluša)
sudo ss -tulnp
sudo lsof -i -P -n | grep LISTEN

1.5 Firewall provjera
sudo iptables -L -n
sudo iptables -S
Ranjivo ako: sve ACCEPT (nema zaštite)
Fix: default DROP + dozvoli samo potrebno

1.6 File permissions (bitan dokaz)
ls -la /etc/shadow
Ranjivo ako: -rw-r--r--
Sigurno: -rw-------

1.7 Kernel verzija
uname -r
Ranjivo: star kernel (stare ranjivosti)
Fix: update/patch




