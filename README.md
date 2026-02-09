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
ls-la sve da vidis
ls -la /etc/shadow
Ranjivo ako: -rw-r--r--
Sigurno: -rw-------

1.7 Kernel verzija
uname -r
Ranjivo: star kernel (stare ranjivosti)
Fix: update/patch

which apparmor_status
Ako izbaci putanju npr /usr/sbin/apparmor_status → postoji.

sudo apparmor_status
Ako piše “profiles are in enforce mode” → aktivno + enforcing 
Ako piše “profiles are in complain mode” → aktivno ali samo upozorava 
Ako kaže “apparmor module is not loaded” → nije aktivan 

Da li servis radi
systemctl status apparmor

2.1 Najbrža provjera statusa SeLinuxa
sestatus

which sestatus


chmod
owner-group-others

Dozvola	Slovo	Broj
read	r	4
write	w	2
execute	x	1

Sabiraš ih.

Primjeri:
r = 4
rw = 4+2 = 6
rx = 4+1 = 5
rwx = 4+2+1 = 7

skripte
touch skripta pravi se
ime="Melloo"
echo "Zdravo $ime"ž
broj=5
echo $broj

unos korisnika
echo "Unesi ime:"
read ime
echo "Zdravo $ime"

if uslov
broj=10

if [ $broj -gt 5 ]; then
    echo "Broj je veci od 5"
fi

for
for i in 1 2 3 4 5
do
    echo $i
done

upis u fajl
echo "tekst" > test.txt

dodavanje u fajl
echo "novi red" >> test.txt

1. Echo koji upisuje drugi echo u fajl
echo "echo 'dobar dan'" > skripta.sh
sa jednim > overwrite
sa dva >>dodajes



