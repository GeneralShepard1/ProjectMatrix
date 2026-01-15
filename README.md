Word Struktura
Mrežna konfiguracija (Kali)
Otkrivanje hostova u mreži
Port scan + servis/OS detekcija
Vulnerabilnosti (po hostu/portu)
Preporuke
Zaključak

Part 1 Osnovna konfiguracija:

1.Boot VM Kali

2.Provjera IP adrese- 
ip a 
Identifikovana ip adresa
Moja je 172.27.170.100/20

AKO TREBAMO SAMI KONFIGURISAT IP ADRESU(TREBACE NA ISPITU REKO GORAN)
sudo systemctl stop NetworkManager->zaustavit network manager da ne smeta
sudo systemctl disable NetworkManager
sudo ip addr flush dev eth0-->OCISTI STARE POSTAVKE
sudo ip addr add 172.27.170.100/20 dev eth0->SETUJES IP ADRESU
sudo ip route add default via 172.27.160.1->SETUJES GATEWAY
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf-->POSTAVIS DNS(nije pod moranje)

ping 172.27.170.100->PROVJERI DA LI RADI
ping google.com->DAL IMAS PRISTUP INTENRETU

Ako dobijemo windows koji trebamo skenirat postavit i njemu rucno ip adresu asmo za 1 vecu
npr moja ip 172.27.170.100/20-> na windows samo tsavimo jednu vise (mora bit u istom subnetu zato 
najbolje jedna vise)->172.27.170.101 i ispod 255.255.240.0
255.255.240.0->ako vam je mreza /20
ako je mreza /24 onda 255.255.255.0

ako trebamo testirat povezanost sa kalija samo pingamo windowsovu ip adresu u konzoli, ako
radi top
ako ne provjeri ponovo sve


pogledat 
ls -la sve fajlove i njihove dozvole
chmod o-w <file>->da sklonimo write za druge


Part 2:Skeniranje ranjivosti SVOJE MASINE ako bude:

Skeniramo lokalne servise
netstat -tln
21 - FTP → Plain text lozinke, rjesenje:koristiti sftp/ftps
annonymus login moguc
22 - SSH → Brute force->ssh key auth,fail2ban->ssh -v user@IP provjervanje verzije ssh(NE SMIJE BITI V1!!!!!!)
23 - Telnet->Plain text->onemoguciti koristiti ssh
80 - HTTP → MITM, sniffing->rjesenje koristit https 
445 - SMB → EternalBlue->windows patch,onemoguciti smbv1
3306 - MySQL → No password->jaka lozinka ili rate limit
5432 - PostgreSQL → Reverse shell->firewaall autentikacija

sudo nmap -sV --script default <ip>
za bolju enumeraciju


DNS ranjivost
cat /etc/resolv.conf
ako nam je gateway npr 172.27.160.1 ranjivo je ako je mali broj kao
1.1.1.1 znaci da je javni server i da je zasticeno
Ranjivost:DNS Spoofing moguc na lokalnom serveru jer korisitmo lokalni dns server koji je isti kao gateway
Napadac moze lazirati dns odgovore i preusmjeriti nas 
Rjesenje:prebaciti dns na pouzdan javni dns(8.8.8.8, 1.1.1.1).



ARP ranjivost
ip neigh show
172.27.160.1 dev eth0 lladdr 00:15:5d:01:40:00 STALE,REachable,Delay->output ranjiv
172.27.160.1 dev eth0 lladdr 00:15:5d:01:40:00 PERMANENT->output siguran
Ranjivost:Arp Spoofing/Man in the middle moguc  jer arp tablica nema fiksne unose.
Napadac moze poslati lazne arp poruke i preusmjeriti saobracaj kroz sebe
kako poopraviti: potsaviti staticki arp unos za gateway




DHCP ranjivost
cat /var/lib/dhcp/dhclient.leases
Ako je prazno tj preskoci onda je ranjivo
Ako npr ima option dhcp server identifier onda je sigurno(option dhcp-server-identifier 172.27.160.1;)
Ranjivost:DHCP spoodinf je moguc jer dhcp klijent prihvata odgovore od bilo gako u mrezi.
Napadac moze poknureit lazni dhcp i davati lazne mrezne potavke
Rjesenje:Konfigurisati dhcp da prihvata samo od oredjenog servera,dhcp snooping


Mac flooding
sudo macchanger -r eth0
ping 172.27.160.1
ako ping radi switch nema port security, switch ranjiv na mac flooding
ako ping prestane radit ima port security



Sniffing ranjivost
ip link show eth0
Ako vidiš PROMISC → Ranjivo (interface u promiskuitetnom modu)
Ako ne vidiš PROMISC → Sigurno
Ranjvisot: Interface je u promiscuous modu što znači da može snimati sve pakete 
u mreži, ne samo one namijenjene njemu.
rjesenje:Onemogućiti promiscuous mode (ip link set eth0 promisc off).




Ako imamo vpn upalljen
nmap -sV -p 1723 <vpn_server>
Moze biti offline crackovan
rjesenje open vpn ili ipsec/ikev2al 

Arp poisoning ranjivost
cat /proc/sys/net/ipv4/conf/all/arp_accept
1-ranjivo
0-sigurno



Testiramo file permissions
ls -la /etc/shadow
-rw-r--r-- nesigurno jer svi mogu citati
-rw------- sigurno(samo root)
Ranjivost:svi korisnici mogu citati hashirane lozinke iz shadow datotoke.
Napadac moze preuzeti hashove i crackovati ih offline
Rjesenje:ograniciti pristup

Skeniramo kernel verziju
uname -r 
ako je starije od 5.x ranjivo,staro, ima poznate ranjivosti iz prolosti
ako je novije sigurno,patchirano

Skeniramo firewall
sudo iptables -L -n
svi lanci accept->ranjivo, nema firewall zastite moze pristupiti bilo ko
Konfigurisati firewall da blkira sve ulazne konekcije osim dozvolljenih
sigurno ako ima input/forward policy drop


Part 3 skeniranje druge masine npr Windowsa:

1.Pronalazimo sve masine 
sudo arp-scan --localnet 
sudo nmap -sn 172.27.170.0/20

prvo skeniramo da vidimo verziju windowsa
nmap -O <ip>


2.Port skeniranje(jako bitno vjv ce morat se ovo radit na ispitu)
nmap  <ip adresa koga skeniramo>
detaljni nmap: nmap -sS -sV -O <ip>

PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn->smbv1(eternal blue)
445/tcp   open  microsoft-ds->smbv3(smbGhost)
3389/tcp  open  ms-wbt-server->BlueeKeep(cve-2019-0708)



3.Skeniranje ranjivosti
nmap --script vuln <ip>

Ako zelimo posebno neku ranjivost skenirat samo dodamo broj porta i njeno ime npr
portv 445 za smb ranjivost

nmap --script smb-vuln* <ip> -p 445

detaljno skeniranje
nmap -sS -sV -O 172.27.170.101


Part 5 ako dobijemo skenirat IP neki sa servisima (vrlo moguce)
1.Full port scan
nmap -p- <ip dobijeni>
OUTPUT:
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
3389/tcp  open  ms-wbt-server
8080/tcp  open  http-proxy

Port 21 — FTP
Vulnerabilnosti:
FTP šalje username/password u plain-text (sniffing)
Anonymous login može biti uključen
verzija servera se vidi → lakše naći CVE
nmap --script ftp-anon -p21 127.0.0.1 ->Provjera anonymous login


provjera ssh: ssh -v
port 22 ssh: ssh password authentication, brute force napad je moguc jer ssh prihvata lozinke
Rjesenje:omoguciti password auth i zahtijevati ssh kljuceve
Provjeriti ssh verziju, ako je 1 ima ranjivosti , forsirati koristenje sshv2



port 23 :Telnet
Vulnerabilnosti:
sve je plain-text (username/password)
lako se presretne
Rješenje:
ugasiti telnet
koristiti SSH



port 80 http:
Ako je http a ne https plain text komunikacija svi podaci se salju nekriptovano
forsisrati https sa ssl certifikatom
ako je apache upaljen
napadac moze vidjeti listu fajlova i foldera
onemoguciti directory listing u apache konfiguraciji
provjera:nmap --script http-title,http-headers -p80 127.0.0.1
Rješenje:
koristiti HTTPS (443)
ugasiti directory listing
update web server


port 139:netbios-ssn
ranjiv na eternalbue
patchati windows

port 443:https
sslscan <ip>
slabe kritptografske protokole je lako rpibiti
onemoguciti ssl v3 i tlsv1
Provjeriti dal je certifikat istekao

port 445:SMB
EternalBlue na ranijiim verzjiama widnwosa,omogucava remote code execution nmap -sV -p445 127.0.0.1
onemoguciti smbv1 i instlirati windwos patchirano
SMB ghost na v3 omogucava isto remote code exec. nmap --script smb-vuln* -p445 <IP>
instalirati microsoft patch i blokirati port 445

port 3306 mysql
bilo ko moze pristupiti bazi podataka sa root privlieegijama
postaviti jaku lozinku na root

Vulnerabilnosti:
root bez šifre
MySQL otvoren prema mreži
brute force
Rješenje:
jaka šifra
bind na localhost (samo lokalno)
firewall blokirati 3306 eksterno

Port 5432 — PostgreSQL
nmap -sV -p5432 127.0.0.1
Vulnerabilnosti:
otvoren prema mreži bez kontrole
slabe šifre
Rješenje:
firewall
autentikacija
bind samo localhost ako ne treba mrežno


instalacija metaslploita
sudo apt update
sudo apt install metasploit-framework -y
msfconsole --version->provjeri verziju
sudo msfdb init->init metaslploit baze
msfconsole->udji u msf
set PORTS 21,22,23,25,53,80,110,135,139,143,443,445,3389,3306,5432,1433,8080
run

use auxiliary/scanner/ftp/ftp_version
run

use auxiliary/scanner/ftp/anonymous
run
ranjivost ako se mozes ulogirat na ftp ko anonymus

use auxiliary/scanner/ssh/ssh_version
set RPORT 22
run

use auxiliary/scanner/http/http_version
set RPORT 80
run

use auxiliary/scanner/http/title
set RPORT 80
run

use auxiliary/scanner/http/dir_scanner
set RPORT 80
set PATH /
run

use auxiliary/scanner/http/robots_txt
set RPORT 80
run

use auxiliary/scanner/smb/smb_ms17_010
set RPORT 445
run

use auxiliary/scanner/smb/smb_signing
set RPORT 445
run

Provjera otvorenih konekcija + sumnjivih portova
sudo ss -tunap
Vulnerabilnost: sumnjivi proces sluša na portu (backdoor, malware)
Fix: ugasiti servis / ukloniti paket

Provjera aktivnih serivsa:
systemctl list-units --type=service --state=running
Vulnerabilnost: nepotrebni servisi running → veća attack surface
Fix: disable/stop nepotrebne

koji proces drži port
sudo lsof -i -P -n | grep LISTEN

Provjera default šema za korisnike (lokalno)
cat /etc/passwd | cut -d: -f1
Vulnerabilnost: nepotrebni useri / loše postavke
Fix: zaključati/ukloniti korisnike

provjera update statusa
apt list --upgradable


ULTIMATIVNI REDOSLIJED (kratko “cheat list”)

ip a
(ako treba) ručno IP + gateway + DNS
ping gateway + ping google.com
arp-scan --localnet
nmap -sn subnet
za najvažniji host: nmap -p- <ip>
nmap -sS -sV -O <ip>
specifično po portovima:
445: smb-vuln*
3389: rdp-enum-encryption
80: http-methods, http-title, http-headers
443: ssl-enum-ciphers
21: ftp-anon
22: ssh2-enum-algos
nmap --script vuln <ip> (bonus)
sve dokumentuj: komanda + output + fix


ip a
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager
sudo ip addr flush dev eth0
sudo ip addr add 172.27.170.100/20 dev eth0
sudo ip route add default via 172.27.160.1
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
ping -c 2 172.27.160.1
ping -c 2 8.8.8.8
ping -c 2 google.com
sudo arp-scan --localnet
sudo nmap -sn 172.27.170.0/20# 1) Provjera IP / interface

Redosljed komandi


ip a

# 2) (AKO NEMA IP) Rucna konfiguracija mreze (zamijeni po potrebi)
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager
sudo ip addr flush dev eth0
sudo ip addr add 172.27.170.100/20 dev eth0
sudo ip route add default via 172.27.160.1
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# 3) Provjera konekcije
ping -c 2 172.27.160.1
ping -c 2 8.8.8.8
ping -c 2 google.com

# 4) Pronalazak hostova u mrezi
sudo arp-scan --localnet
sudo nmap -sn 172.27.170.0/20

# 5) Izaberi target IP iz liste i stavi ga ovdje (PROMIJENI OVO)
TARGET=172.27.170.101

# 6) OS detekcija (brzo)
sudo nmap -O $TARGET

# 7) Full port scan (svi portovi)
sudo nmap -p- $TARGET

# 8) Detaljni scan (servisi + verzije + OS)
sudo nmap -sS -sV -O $TARGET

# 9) Vuln scan (generalno)
sudo nmap --script vuln $TARGET

# =========================
# SPECIFICNE PROVJERE PO PORTOVIMA
# =========================

# 10) SMB (445) - OS discovery + security mode
sudo nmap --script smb-os-discovery,smb-security-mode -p445 $TARGET

# 11) SMB ranjivosti (EternalBlue i ostalo)
sudo nmap --script smb-vuln* -p445 $TARGET

# 12) NETBIOS/SMB (139)
sudo nmap -sV -p139 $TARGET

# 13) RDP (3389)
sudo nmap -sV -p3389 $TARGET
sudo nmap --script rdp-enum-encryption -p3389 $TARGET

# 14) HTTP (80)
sudo nmap -sV -p80 $TARGET
sudo nmap --script http-title,http-headers,http-methods,http-robots.txt -p80 $TARGET

# 15) HTTPS (443)
sudo nmap -sV -p443 $TARGET
sudo nmap --script ssl-enum-ciphers -p443 $TARGET

# 16) FTP (21)
sudo nmap -sV -p21 $TARGET
sudo nmap --script ftp-anon,ftp-banner,ftp-syst -p21 $TARGET

# 17) SSH (22)
sudo nmap -sV -p22 $TARGET
sudo nmap --script ssh2-enum-algos -p22 $TARGET

# 18) Telnet (23)
sudo nmap -sV -p23 $TARGET

# 19) SMTP (25)
sudo nmap -sV -p25 $TARGET

# 20) DNS (53)
sudo nmap -sV -p53 $TARGET

# 21) MySQL (3306)
sudo nmap -sV -p3306 $TARGET

# 22) PostgreSQL (5432)
sudo nmap -sV -p5432 $TARGET

# 23) MSSQL (1433)
sudo nmap -sV -p1433 $TARGET

# 24) HTTP proxy / app server (8080)
sudo nmap -sV -p8080 $TARGET
sudo nmap --script http-title,http-headers,http-methods -p8080 $TARGET

# =========================
# LOKALNO (KALI) - DODATNI BODOVI (AKO TREBA SKENIRATI SVOJU MASINU)
# =========================

# 25) Koji portovi slusaju na Kali
sudo ss -tulnp
sudo lsof -i -P -n | grep LISTEN

# 26) Firewall status
sudo iptables -L -n

# 27) DNS konfiguracija (DNS spoofing rizik)
cat /etc/resolv.conf

# 28) ARP tabela (ARP spoofing rizik)
ip neigh show

# 29) Promiscuous mode (sniffing rizik)
ip link show eth0

# 30) Shadow permissions (lokalne lozinke)
ls -la /etc/shadow

# 31) Kernel verzija (patch status)
uname -r

# 32) Brza provjera routing-a i gateway-a
ip route

# 33) Provjeri ARP accept (ARP poisoning rizik)
cat /proc/sys/net/ipv4/conf/all/arp_accept

# 34) Provjeri IP forwarding (MITM/route risk ako je upaljeno)
cat /proc/sys/net/ipv4/ip_forward

# 35) Provjeri da li je ukljucen promiscuous mode (jos jednom brzo)
ip -details link show eth0 | grep -i promisc

# 36) Provjeri aktivne servise (attack surface)
systemctl list-units --type=service --state=running

# 37) Provjera ulogovanih korisnika (lokalna sigurnost)
who
w

# 38) Provjera sudo prava (privilege risk)
sudo -l

# 39) Provjera usera na sistemu (lokalno)
cut -d: -f1 /etc/passwd

# 40) Provjera password policy / login konfiguracije (lokalno)
cat /etc/login.defs | grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE"

# 41) Provjera da li je SSH dozvolio root login (config)
grep -i "^PermitRootLogin" /etc/ssh/sshd_config
grep -i "^PasswordAuthentication" /etc/ssh/sshd_config

# 42) Provjera SSH rekey (hardening)
grep -i "rekey" /etc/ssh/sshd_config

# 43) Provjera dozvoljenih portova kroz firewall (iptables detaljnije)
sudo iptables -S

# 44) Lista "otvorenih" TCP/UDP portova sa Nmap na sebi (lokalni scan)
sudo nmap -sS -sV -O 127.0.0.1
sudo nmap -sU --top-ports 50 127.0.0.1

# 45) Scan subnet-a za najcesce opasne portove (brzo)
sudo nmap -sn 172.27.170.0/20
sudo nmap -sS -sV -O -p 21,22,23,25,53,80,110,135,139,143,443,445,3389,3306,5432,1433,8080 172.27.170.0/20

# 46) Snimi nmap rezultate u fajl (za Word izvjestaj)
sudo nmap -sS -sV -O $TARGET -oN nmap_target.txt
sudo nmap --script vuln $TARGET -oN nmap_vuln.txt

# =========================
# METASPLOIT (Samo skeniranje) - AKO HOCES DODATNI BONUS
# =========================

# 47) Pokreni Metasploit
msfconsole

# 48) U msfconsole (paste inside msf):
# setg RHOSTS 172.27.170.101

# 49) FTP provjere (21)
# use auxiliary/scanner/ftp/ftp_version
# set RPORT 21
# run
# use auxiliary/scanner/ftp/anonymous
# set RPORT 21
# run

# 50) SSH provjere (22)
# use auxiliary/scanner/ssh/ssh_version
# set RPORT 22
# run
# use auxiliary/scanner/ssh/ssh_enumalgos
# set RPORT 22
# run

# 51) HTTP provjere (80)
# use auxiliary/scanner/http/http_version
# set RPORT 80
# run
# use auxiliary/scanner/http/title
# set RPORT 80
# run
# use auxiliary/scanner/http/dir_scanner
# set RPORT 80
# set PATH /
# run
# use auxiliary/scanner/http/robots_txt
# set RPORT 80
# run

# 52) SMB provjere (445)
# use auxiliary/scanner/smb/smb_version
# set RPORT 445
# run
# use auxiliary/scanner/smb/smb_ms17_010
# set RPORT 445
# run
# use auxiliary/scanner/smb/smb_signing
# set RPORT 445
# run

# 53) Spool output u fajl (dokaz)
# spool /home/kali/msf_scan.txt
# spool off
# 54) Brzi "top ports" scan (brzo daje puno info)
sudo nmap --top-ports 100 -sS -sV $TARGET

# 55) Brzi UDP scan (cesto se zaboravi, a donese bodove)
sudo nmap -sU --top-ports 50 $TARGET

# 56) Enumeracija SMB share-ova (ako je 445 otvoren)
sudo nmap --script smb-enum-shares,smb-enum-users -p445 $TARGET

# 57) SMB protokoli / dialects (SMBv1 / SMBv2 / SMBv3)
sudo nmap --script smb-protocols -p445 $TARGET

# 58) SMB sigurnosne postavke (signing)
sudo nmap --script smb2-security-mode -p445 $TARGET

# 59) HTTP - provjera poznatih fajlova i direktorija (common)
sudo nmap --script http-enum -p80 $TARGET
sudo nmap --script http-enum -p8080 $TARGET

# 60) HTTP - provjera TRACE metode (XST rizik)
sudo nmap --script http-trace -p80 $TARGET
sudo nmap --script http-trace -p8080 $TARGET

# 61) HTTP - provjera web aplikacije / CMS fingerprint
sudo nmap --script http-generator -p80 $TARGET

# 62) Provjera da li postoji WordPress/Joomla (ako web radi)
sudo nmap --script http-wordpress-enum -p80 $TARGET

# 63) HTTPS - cert info (istekao/loš cert)
sudo nmap --script ssl-cert -p443 $TARGET

# 64) Provjera slabih SSL/TLS verzija (još jednom)
sudo nmap --script ssl-enum-ciphers -p443 $TARGET

# 65) Provjera prisutnosti proxy/cache headera (info)
sudo nmap --script http-security-headers -p80 $TARGET
sudo nmap --script http-security-headers -p443 $TARGET

# 66) Provjera MySQL info (ako je 3306 otvoren)
sudo nmap --script mysql-info -p3306 $TARGET

# 67) Provjera PostgreSQL info (ako je 5432 otvoren)
sudo nmap --script pgsql-info -p5432 $TARGET

# 68) Provjera MSSQL info (ako je 1433 otvoren)
sudo nmap --script ms-sql-info -p1433 $TARGET

# 69) Provjera SNMP (ako je 161 otvoren)
sudo nmap -sU -p161 $TARGET
sudo nmap --script snmp-info -sU -p161 $TARGET

# 70) Provjera TFTP (ako je 69 otvoren)
sudo nmap -sU -p69 $TARGET

# =========================
# BRZO SPREMANJE REZULTATA (ZA WORD)
# =========================

# 71) Sve u jedan fajl (super za dokaz)
sudo nmap -p- -sS -sV -O $TARGET -oN FULL_SCAN_$TARGET.txt

# 72) Vuln skripte u fajl
sudo nmap --script vuln $TARGET -oN VULN_SCAN_$TARGET.txt

# 73) SMB skripte u fajl (ako je 445 otvoren)
sudo nmap --script smb-os-discovery,smb-security-mode,smb-vuln* -p445 $TARGET -oN SMB_SCAN_$TARGET.txt

# 74) HTTP skripte u fajl (ako je 80 otvoren)
sudo nmap --script http-title,http-headers,http-methods,http-enum,http-robots.txt -p80 $TARGET -oN HTTP_SCAN_$TARGET.txt

# 75) HTTPS skripte u fajl (ako je 443 otvoren)
sudo nmap --script ssl-cert,ssl-enum-ciphers -p443 $TARGET -oN HTTPS_SCAN_$TARGET.txt

# =========================
# LOKALNE SIGURNOSNE PROVJERE (KALI) - BONUS
# =========================

# 76) Provjera kernel hardening vrijednosti (ASLR)
cat /proc/sys/kernel/randomize_va_space

# 77) Provjera da li je ufw aktivan (ako postoji)
sudo ufw status verbose

# 78) Provjera aktivnih mrežnih konekcija (sumnjivo)
sudo ss -tunap

# 79) Provjera zadnjih logina (audit)
last -a | head -n 20
