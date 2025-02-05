## John the ripper

cracking PDF file

- pdf2john Infrastructure.pdf > pdf.hash
- john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 pdf.hash

cracking keepass

- keepass2john database.kdbx > keepass.hash
- remove the Database: string infront of the $ before cracking the hash
  - hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

cracking zip file

- zip2john winrm_backup.zip > zip.john
- john zip.john -wordlist:/usr/share/wordlists/rockyou.txt

cracking PFX file

- python3 /usr/share/john/pfx2john.py legacyy_dev_auth.pfx > pfx.john
- john pfx.john -wordlist:/usr/share/wordlists/rockyou.txt

SSH passphase

- require id_rsa or similar key found
- convert id_rsa into a hash for cracking
  - ssh2john id_rsa > ssh.hash
- remove the filename before the $ sign
- can use `hashcat -h | grep -i "ssh"` to check what hash we have, commonly seen with `$6$`
- john --wordlists=/usr/share/wordlists/rockyou.txt ssh.hash

## Hashcat

try web cracking website as well https://crackstation.net/

DCC hash

- hashcat -m 2100 web_svc.txt /usr/share/wordlists/rockyou.txt
  the hash $DCC2$10240#web_svc#130379745455ae62bbf41faa0572f6d3

MD5 / NTLM hash

- hashcat -m 1000 e7966b31d1cad8a83f12ecec236c384c /usr/share/wordlists/rockyou.txt
- hashcat -m 3200 adminhash.txt /usr/share/wordlists/rockyou.txt

NetNTLMv2

- hashcat -m 5600 mary_ntmlv2.txt /usr/share/wordlists/rockyou.txt

kerberoast hash

- sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
- sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

keepass hash

- hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

## Hydra Bruteforce

POP3

- hydra -L possible_users.txt -P possible_passwords.txt 192.168.113.137 pop3 -V -f

SSH and RDP

- hydra -l user -P /usr/share/wordlists/rockyou.txt -s port# ssh:targetIP
- hydra -L list_users -p password rdp://targetIP

gpp-decrypt

- use to crack cpassword
  - gpp-decrypt encrypt_hash
