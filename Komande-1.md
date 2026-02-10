&nbsp;Komande 

**ip a** - provjerava ip adrese i mrežne interfejse 

**ip addr show eth0** - pokatuje status mrežnog interfejsa eth0 

**sudo ip addr flush dev eth0** - uklanja ip adresu sa mrežnog interfejsa eth0

**sudo ip addr add (ip adresa/subnet) dev eth 0** - dodaje novu ip adresu 

**sudo ip link set dev eth0 down** - deaktivacija mrežnog interneta eth0 

**sudo ip link set dev eth0 up** - aktivacija mrežnog interfejsa eth0 

**pwd** - lokacija gdje se trenutno nalazimo 

**ls - al** - pregled direktorija sa permisijama 

**find \*.sh** pretražuje skripte 

Pretraga po ekstenziji (sve skripte na sistemu)

Najčešće su skripte .sh (bash), .py (Python), .pl (Perl), .php (web).

**find / -type f -name "\*.sh" 2>/dev/null**

**find / -type f -name "\*.py" 2>/dev/null**

**find / -type f -name "\*.php" 2>/dev/null**

2>/dev/null sakriva greške tipa Permission denied.

**ls -l (ime skripte)**  - pokazuje ppermisije koje skripta ima 

**ps aux** - prikazuje sve procese sa dodatnim informacijama 

**kill (PID)** - ubijanje procesa

**netstat -tulnp** - prikaz mrežnih veza, protova... (može i netstat -al)

**whoami** - pokazuje koji je korisnik na sistemu

&nbsp;Secure Boot + Supervisor / Administrator password u UEFI

GRUB (skraćenica za GNU Grand Unified Bootloader) je pokretač operativnog sistema (boot loader) koji se koristi u mnogim Linux distribucijama i drugim Unix-sličnim sistemima. Njegova glavna funkcija je da omogući korisniku da izabere koji će operativni sistem da pokrene ukoliko na računaru postoje više instaliranih sistema, ili da izabere specifičnu konfiguraciju kernela za postojeći sistem

LINUX: shell sa promptom ( Init=/bin/bash Nakon toga nastavljamo boot sa CTRL+X) Nakon svakog reda komandi kuca se ENTER: 

1\. mount -o remount,rw ... (radimo mountanje file sistema sa read i write permisijama)

&nbsp;2. mount -a .... (mountanje svih fajl sistema)

&nbsp;3. useradd -m -s /bin/bash -G sudo hacker ...(dodaj korisnika, kreiraj mu home direktorij, dodjeli mu shell – bash, dodaj ga u grupu sudo, korisnik hacker)

&nbsp;4. passwd hacker – definišemo lozinku za korisnika hacker 

5\. sync – sinkamo sistem 

6\. mount -o remount,ro / .... (radimo ponovno mountanje sa read only) 

7\. reboot -f ... (restartamo sistem)

Mjere sprečavanja ovakvog napada: Svaki sistem kojem korisnik ima ovakav pristup je ranjiv na ovakav napad. Kako se možemo zaštiti od ovog napada? Možemo preko niza mjera kao što su:

&nbsp;1. setovanje lozinke na GRUB

&nbsp;2. postaviti permisije na pristup GRUB u 

3\. Kao i kod windowsa i kod Linuxa možemo kriptovati disk (LUKS)

**netstat -rn** -pokazuje routing tabelu 

**nmap -sV (ip adresa)** - prikazuje otvorene portove i verzije servisa

**cat /etc/passwd** -prikaz svih korisnika 

**nikto -h http://(ipadresa)** - pregleda http headere

**nmap -p (br porta) (ip adresa)** - provjerava sta se radi na portu 

 **id (kor. ime)** - provjerava korisnika po imenu 

**find / -user korisnicko\_ime 2>/dev/null** - fajlovi koje koruisnik posjeduje 

**sudo deluser korisnicko\_ime sudo** - brise korisnika iz sudo grupe

**sudo deluser korisnicko\_ime** -brise korisnika

**sudo rm nazivDokumenta** - brise dokument

**cat nazivDokumenta** -provjerava sadrzaj dokumenta

**ls -l /etc/shadow** - provjerava permisije fajla shadow /etc/shadow sadrži heširane lozinke svih korisnika Ako vidiš nešto tipa:

-rw-r--r-- 1 root root ...

To je kritična ranjivost, jer svi korisnici mogu čitati lozinke.



**find / -perm -4000 2>/dev/null**

Šta radi: Traži sve fajlove sa SUID bitom (-4000).

Zašto je bitno:

SUID = “Set User ID” → kada se fajl pokrene, izvršava se sa privilegijama vlasnika (obično root).

Normalno, samo određeni programi imaju SUID (npr. /usr/bin/passwd).

Primjer izlaza:

/usr/bin/passwd

/usr/bin/sudo

/usr/bin/chsh

Ako nađeš neki čudan fajl sa SUID bitom (npr. backup.sh ili test), to je ranjivost jer omogućava eskalaciju privilegija.

**nc -zv (ip adresa) (range broja portova)** - skenira portove u tom rangu



**Najčešće kritični portovi i zašto su rizični**

**Port	  Protokol/Servis	        Zašto je kritičan**

**21	        FTP	                Često dozvoljava anoniman login; loše enkripcije.**

**22	        SSH	                Ako ostane na default portu, meta brute‑force napada.**

**23	        Telnet	                Prenosi podatke u čistom tekstu (bez enkripcije).**

**25	        SMTP	                Može se zloupotrijebiti za spam ili phishing.**

**53	        DNS	                DNS poisoning, amplification napadi.**

**80	        HTTP	                Najčešći web port; meta SQLi, XSS, RCE napada.**

**443	        HTTPS	                Ako je loše konfigurisan SSL/TLS, ranjiv na MITM.**

**110 / 143	POP3 / IMAP	        Prenose email lozinke u čistom tekstu ako nema TLS.**

**445	        SMB	                Česte ranjivosti (npr. EternalBlue exploit).**

**3306	        MySQL	                Ako je otvoren prema internetu, meta za credential stuffing.**

**3389	        RDP	                Česta meta brute‑force i ransomware napada.**

**5900	        VNC	                Prenosi sesije bez jake enkripcije.**









