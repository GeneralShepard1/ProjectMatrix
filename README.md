
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



Part 2:Skeniranje ranjivosti SVOJE MASINE ako bude:

Skeniramo lokalne servise
netstat -tln
21 - FTP → Plain text lozinke, rjesenje:koristiti sftp/ftps
annonymus login moguc
22 - SSH → Brute force->ssh key auth,fail2ban
23 - Telnet->Plain text->onemoguciti koristiti ssh
80 - HTTP → MITM, sniffing->rjesenje koristit https 
445 - SMB → EternalBlue->windows patch,onemoguciti smbv1
3306 - MySQL → No password->jaka lozinka ili rate limit
5432 - PostgreSQL → Reverse shell->firewaall autentikacija


DNS ranjivost
cat /etc/resolv.conf
ako nam je gateway npr 172.27.160.1 ranjivo je ako je mali broj kao
1.1.1.1 znaci da je javni server i da je zasticeno
Ranjivost:DNS Spoofing moguc na lokalnom serveru jer korisitmo lokalni dns server koji je isti kao gateway
Napadac moze lazirati dns odgovore i preusmjeriti nas 
Rjesenje:prebaciti dns na pouzdan javni dns(8.8.8.8, 1.1.1.1).



ARP ranjivost
ip neigh show
172.27.160.1 dev eth0 lladdr 00:15:5d:01:40:00 STALE->output ranjiv
172.27.160.1 dev eth0 lladdr 00:15:5d:01:40:00 PERMANENT->output siguran
Ranjivost:Arp Spoofing/Man in the middle moguc  jer arp tablica nema fiksne unose.
Napadac moze poslati lazne arp poruke i preusmjeriti saobracaj kroz sebe
kako poopraviti: potsaviti staticki arp unos za gateway




DHCP ranjivost
cat /etc/dhcp/dhclient.conf
Ako je prazno tj preskoci onda je ranjivo
Ako npr ima option dhcp server identifier onda je sigurno(option dhcp-server-identifier 172.27.160.1;)
Ranjivost:DHCP spoodinf je moguc jer dhcp klijent prihvata odgovore od bilo gako u mrezi.
Napadac moze poknureit lazni dhcp i davati lazne mrezne potavke
Rjesenje:Konfigurisati dhcp da prihvata samo od oredjenog servera


Mac flooding
sudo macchanger -r eth0
ping 172.27.160.1
ako ping radi switch nema port security, switch ranjiv na mac flooding
ako ping prestane radit ima port security

replay attack
grep -i "rekey" /etc/ssh/sshd_config
Ako nema RekeyLimit postavke → Potencijalno ranjivo
RekeyLimit 1G 1h → Sigurno

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



port 22 ssh: ssh password authentication, brute force napad je moguc jer ssh prihvata lozinke
Rjesenje:omoguciti password auth i zahtijevati ssh kljuceve
Provjeriti ssh verziju, ako je 1 ima ranjivosti , forsirati koristenje sshv2


port 80 http:
Ako je http a ne https plain text komunikacija svi podaci se salju nekriptovano
forsisrati https sa ssl certifikatom
ako je apache upaljen
napadac moze vidjeti listu fajlova i foldera
onemoguciti directory listing u apache konfiguraciji

port 139:netbios-ssn
ranjiv na eternalbue
patchati windows

port 443:https
sslscan <ip>
slabe kritptografske protokole je lako rpibiti
onemoguciti ssl v3 i tlsv1
Provjeriti dal je certifikat istekao

port 445:SMB
EternalBlue na ranijiim verzjiama widnwosa,omogucava remote code execution
onemoguciti smbv1 i instlirati windwos patchirano
SMB ghost na v3 omogucava isto remote code exec.
instalirati microsoft patch i blokirati port 445

port 3306 mysql
bilo ko moze pristupiti bazi podataka sa root privlieegijama
postaviti jaku lozinku na root


1. fizicki sloj ranjiv na fizicki pristup,snifanje saobracaja
2.data link sloj(mac sloj) manipulacija mac adtresama,mac spoofingmac flooding,man in the middle)
3.network sloj fokusiran na protkole,smurf attack 
4.transportni sloj vezan za portove,otmice sesije,dos napad zloupotrebom protokola
5.sesijski sloj,otmice sesija, cross side scripting
6.prezentacijski sloj, obmanjivanje korisnika phising napadi
7.aplikacijski sloj napadac koristi pripremljene skripte programcice exploiiute da bi kompromitovao

Najcesci prtpookoli koji mogu biti predmet napada
1.DNS(ako stane dns staje mreza)
2.SMB-dijeli resurse na niovu mreze.
3.ssh(secure shell)kritpovano povezivanje na remote racunar i komunikacija
4.http (treba imat tls ssl )dodatni sloj koji omogucava enkripciju komunikacije
5.vpn protokol oslanja se na skup protokola sa data i network sloja
6.dhcp konfigurise ip adrese u mrezi

Pasivni napadi:sniffanje paketa,mac floodanje,arp poisoning
Aktivni napadi:man in the middle,port scanning, dos/ddos napadi,brute force autentifikacija

Ranjivi mrezni protokoli:

1.smb:eternal blue ranjivost kod smb v1
      samba cry ranjivost samba servera
	  smbghost- remote code execution
mjere protiv:blokirati smbv1,aktiivrati smb potpisivanje autentifikacije,primjenit princip privilegija,
             redovna primjena patcheva,segmentirati mrezu i blokirati nepotrebne portove(445,139)

2.DNS:dns spoofing(ubacivanje laznih dns odgovora)
      dns cache poisoning(trovanje dns servera, varanje i slanje ip adrese prema laznom web serveru)
mjere protiv:imlementacija DNSSEC,upotreba split horizon dns,redovan update dnsa,ogranicavanje samo na
      autorizovane servere,rate limit,dhcp snooping

3.http:phising(vjerna lazna kopija)
       saobracaj u plain tekstu
	   cookies-informacije u sesiji se pohrane u plain text 
	   sesion hijacking-otimanje sesije
	   reply napad-napadc presretne legitimni opdatak i ponovo ga posalje serveru
	   sql injection ubacivanje sql komandi u polja
	   XSS xcross site scripting-insert koda u postojecu web app
mjere protiv:tls certifikat, uvijek koristit https,implementiraj hsts,validiraj input,koristi secure cookies,
             redovan patch web servera i app
			 
4.ssh:ssh v1 je neisguran zbog slabe enkripcije i integriteta
      ssh v2 sigurniji al losom konfiguracijom moze bit zajeban
	  napadi:brute force,verifikacija servery key fingerprinta,agent hijacking,
mjere protiv:koristenje sshv2,onemoguci password auth nego key based auth,mfa aktivacija,
             ogranicen agent forwarding,postavit fail2ban

5.ip protokol:ip spoofing(laziranje ip adrese)
               tcp syn flood(napadac kreira modifikovan ip paket i lazira svoju ip adresu,salje ih stalno i 
			   obori server
               smurf attack(salje pakete spoofanom ip adrom vecemb roju hostova i preplavi saobracaj)
               LAND attack(ne moze poslije windows 98,lazira izorisnu i destinacijsku ip dovede do crasha)
mjere protiv:ip source gouard

6.arp protokol:arp spoofanje(laziranje arp odgovora)
               man in the middle(napadc se pozicionira izmedju zrtve i destinacija
mjere protiv:dynamic arp inspection,koristenje statickog arpa

7.DHCP:Rogue dhcp server(lazni dhcp server)
       dhcp starvation(spofanje mac adrese s koje salje zahtjev, iscrpi sve adrese i ne moze dhcp
	   dodijelit ip adresu)
mjere protiv:dhcp snooping,rate limit,port security,

			   
		
