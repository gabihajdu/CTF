Sniper IP:10.10.10.151



rustscan:
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
49667/tcp open  unknown      syn-ack



nmap:

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Sniper Co.
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 7376/tcp): CLEAN (Timeout)
|   Check 2 (port 18459/tcp): CLEAN (Timeout)
|   Check 3 (port 51336/udp): CLEAN (Timeout)
|   Check 4 (port 58751/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-04-11T20:59:16
|_  start_date: N/A



enum4linux:

enum4linux -v 10.10.10.151                                                                                                                                                                   1 ⨯
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Apr 11 09:57:26 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.151
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.151    |
 ==================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.10.151'
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.151    |
 ============================================ 
Looking up status of 10.10.10.151
No reply from 10.10.10.151

 ===================================== 
|    Session Check on 10.10.10.151    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.10.151'/ipc$ -U''%'' -c 'help' 2>&1
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.




nikto:

nikto -h 10.10.10.151
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.151
+ Target Hostname:    10.10.10.151
+ Target Port:        80
+ Start Time:         2023-04-11 09:56:56 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: PHP/7.3.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Cookie PHPSESSID created without the httponly flag
+ 7863 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2023-04-11 10:06:25 (GMT-4) (569 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested






smbclient:

└─$ smbclient -N -L ///10.10.10.151                                                                                                                                                              1 ⨯
session setup failed: NT_STATUS_ACCESS_DENIED

gobuster;

gobuster dir  -u http://10.10.10.151  -w /usr/share/wordlists/dirb/common.txt -t 64   
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.151
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/04/11 10:17:59 Starting gobuster
===============================================================
/blog (Status: 301)
/Blog (Status: 301)
/css (Status: 301)
/images (Status: 301)
/Images (Status: 301)
/index.php (Status: 200)
/js (Status: 301)
/user (Status: 301)
===============================================================
2023/04/11 10:18:07 Finished
==================================

