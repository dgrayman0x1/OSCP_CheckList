#### Nmap

-> regular scan

- sudo nmap -sC -sV -O -A -p- -T4 $ip

-> UDP scan

- sudo nmap -sU --top-ports 1000 $ip

#### Gobuster

-> /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
-> /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt

-> regular scan

- gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt

-> PHP extension scan

- gobuster dir -u http://10.10.10.84 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/raft-small-words-lowercase.txt -x php

#### Feroxbuster

-> regular scan

- feroxbuster -u http://192.168.199.143:80/ -w /usr/share/seclists/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt --depth 3

#### Wordpress Scan

-> regular scan

- sudo wpscan --url http://example.com

---

#### Port Check

-> **21 - FTP**

- anonymous login
- file upload, file download
- login with password reuses, try default credentials
- brute force login using hydra
  - hydra -l admin -P /usr/share/seclists/SecLists-master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$ip

-> **22 - SSH**

- anonymous login
- use ssh key to login
  - ssh -i <dt_key> -p 2222 user@ip

-> **25 - SMTP**

- run nmap
  - sudo nmap -sV -p25,465,587 --script _smtp_ $ip
- enumerate users with a username list
  - smtp-user-enum -U possible_users.txt -t $ip
- brute force SMTP

  -> **80 & 443 / HTTP**

- default login
- check page source code
- check for directory traversal or SQLi

-> **110 - POP3**

- scan
  - nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p 106-1000 $ip
- login
  - telnet $ip $port

-> **139 & 445 - SMB**

- sudo nmap -Pn -p139 -T4 --script "discovery and smb\*" $ip
- SMBCLIENT
  - log in with credential
    - smbclient -U user%password //$ip/share
    - smbclient //$ip/share -U $user
  - download files
    - smbclient //$ip/share
  - list all users
    - smbclient -L //$ip
  - anonymous sign in
    - smbclient -U '' -L \\\\$ip\\
  - anonymous shares access
    - smbclient //$ip/share --option="client min protocol=core" -U ''
- SMBMAP
  - login with credential
    - smbmap -d domain.com -u user -p password -H $ip
  - login as guess
    - smbmap -H $ip -u guest -d domain.com
  - potentials users enumerate
    - cme smb $ip --users
  - checking for READ/WRITE permission/List shares without passwords
    - smbmap -H $ip

-> **161 - SNMP**

- scan
  - sudo nmap -sU -p161 --script _snmp_ $ip
  - snmpbulkwalk -Cr1000 -c public -v2c $ip . > snmpwalk.1
  - snmpwalk -c public $ip -v 2c -OXva NET-SNMP-EXTEND-MIB::nsExtendObjects
  - snmpwalk -v 2c -c public $ip NET-SNMP-EXTEND-MIB::nsExtendOutputFull NET-SNMP-EXTEND-MIB::nsExtendOutputFull."RESET" = STRING:

-> **593 - RPC**

- Enumerating shared resources, users, or groups anonymously with rpcclient
  - rpcclient -U "" -N $ip
    - enumdomusers option

-> **3306 - mySQL**

- linux ver
  - mysql -h $IP -u $user

-> **5437 - postgreSQL**

- connect with default cred
  - psql -U postgres -p 5437 -h $ip
