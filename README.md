# Linux Network, Security & Bash Basics

Ovaj dokument sadrži osnovne Linux komande za provjeru mreže, sigurnosti sistema, permisija, firewall-a i osnova bash skripti.

---

## 1. Network Configuration

### 1.1 Provjera IP adrese

```bash
ip a
```

Prikazuje sve mrežne interfejse i dodijeljene IP adrese.

---

### 1.2 Ručna konfiguracija mreže (ako nema IP adrese)

```bash
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager
sudo ip addr flush dev eth0
sudo ip addr add 172.27.170.100/20 dev eth0
sudo ip route add default via 172.27.160.1
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

Koristi se kada mreža nije automatski konfigurisana.

---

### 1.3 Provjera konekcije

```bash
ping -c 2 172.27.160.1
ping -c 2 8.8.8.8
ping -c 2 google.com
```

- provjera gateway-a  
- provjera internet konekcije  
- provjera DNS rezolucije  

---

### 1.4 Lokalni portovi (šta sluša na sistemu)

```bash
sudo ss -tulnp
sudo lsof -i -P -n | grep LISTEN
```

Prikazuje aktivne servise i otvorene portove.

---

### 1.5 Firewall provjera

```bash
sudo iptables -L -n
sudo iptables -S
```

Ranjivo stanje:
Ako su sve politike ACCEPT → nema zaštite.

Preporuka:
Default politika DROP i dozvoliti samo potrebne portove.

---

### 1.6 File permissions (bitan dokaz)

```bash
ls -la
ls -la /etc/shadow
```

Ranjivo:
-rw-r--r--

Sigurno:
-rw-------

---

### 1.7 Kernel verzija

```bash
uname -r
```

Star kernel može sadržavati poznate ranjivosti.

Fix:
Update sistema i patchiranje.

---

### 1.8 AppArmor provjera

```bash
which apparmor_status
sudo apparmor_status
systemctl status apparmor
```

Status:
- enforce mode → aktivno i štiti
- complain mode → samo upozorava
- module is not loaded → nije aktivan

---

### 1.9 SELinux provjera

```bash
sestatus
which sestatus
```

Najbrža provjera statusa SELinux-a.

---

## 2. Linux Permissions (chmod)

Dozvole:

read (r) = 4  
write (w) = 2  
execute (x) = 1  

Sabiranjem dobijamo:

r = 4  
rw = 6  
rx = 5  
rwx = 7  

Struktura:
owner - group - others

---

## 3. Bash Skripte – Osnove

### Kreiranje skripte

```bash
touch skripta.sh
```

---

### Varijable

```bash
ime="Melloo"
echo "Zdravo $ime"

broj=5
echo $broj
```

---

### Unos korisnika

```bash
echo "Unesi ime:"
read ime
echo "Zdravo $ime"
```

---

### IF uslov

```bash
broj=10

if [ $broj -gt 5 ]; then
    echo "Broj je veci od 5"
fi
```

---

### FOR petlja

```bash
for i in 1 2 3 4 5
do
    echo $i
done
```

---

### Upis u fajl

```bash
echo "tekst" > test.txt
```

Overwrite fajla.

---

### Dodavanje u fajl

```bash
echo "novi red" >> test.txt
```

Dodavanje na kraj fajla.

---

### Echo koji upisuje drugi echo u fajl

```bash
echo "echo 'dobar dan'" > skripta.sh
```

---

### Bash sabiranje brojeva

```bash
#!/bin/bash

a=5
b=3

rezultat=$((a + b))

echo $rezultat
```
