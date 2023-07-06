Teacher IP:10.10.10.153


rustscan:

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack



nmap:


PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Blackhat highschool


nikto:



gobuster:

gobuster dir -u http://teacher.htb -w /usr/share/wordlists/dirb/common.txt -t 64
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://teacher.htb
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/06 19:49:34 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 290]
/.htaccess            (Status: 403) [Size: 295]
/.htpasswd            (Status: 403) [Size: 295]
/css                  (Status: 301) [Size: 308] [--> http://teacher.htb/css/]
/fonts                (Status: 301) [Size: 310] [--> http://teacher.htb/fonts/]
/images               (Status: 301) [Size: 311] [--> http://teacher.htb/images/]
/index.html           (Status: 200) [Size: 8028]
/javascript           (Status: 301) [Size: 315] [--> http://teacher.htb/javascript/]
/js                   (Status: 301) [Size: 307] [--> http://teacher.htb/js/]
/manual               (Status: 301) [Size: 311] [--> http://teacher.htb/manual/]
/moodle               (Status: 301) [Size: 311] [--> http://teacher.htb/moodle/]
/phpmyadmin           (Status: 403) [Size: 296]
/server-status        (Status: 403) [Size: 299]
Progress: 4408 / 4615 (95.51%)
===============================================================
2023/05/06 19:49:41 Finished
===============================================================




/manual -> 


visiting /images we are presented with a list of images. However when trying to view image 5, we get an error. Let's open BurpSuite and check the image out.

When viewing image 5, this is not openeing, and we get an error:  The image from teacher.htb/images/5.png cannot be displayed because it contains errors.

 However, when we open the request in burp, we get the following info:


Hi Servicedesk,

I forgot the last charachter of my password. The only part I remembered is Th4C00lTheacha.

Could you guys figure out what the last charachter is, or just reset it?

Thanks,
Giovanni


Nice, it seem that we have a part of an password.

I am convinced that this is part of the password from teacher.htb/moodle, where there is a user called giovanni. Here there is a log in,but first we need to create a list of passwords in order to brute force it.

Create a wordlist:


┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Teacher]
└─$ python3 -c 'import string; print("\n".join([f"Th4C00lTheacha{c}" for c in string.printable[:-5]]))' > passwords


Now we use burpsuite intruder with sniper attack on giovanni account and we find that the correct password is :Th4C00lTheacha# 


now let's log in to the account. it works. time to search for an exploit:


──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Teacher]
└─$ searchsploit moodle
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Mambo Component Mam-Moodle alpha - Remote File Inclusion                                                                                                                                                   | php/webapps/2064.txt
Moodle - Remote Command Execution (Metasploit)                                                                                                                                                             | linux/remote/29324.rb
Moodle 1.1/1.2 - Cross-Site Scripting                                                                                                                                                                      | php/webapps/24071.txt
Moodle 1.5.2 - 'moodledata' Remote Session Disclosure                                                                                                                                                      | php/webapps/3508.txt
Moodle 1.5/1.6 - '/mod/forum/discuss.php?navtail' Cross-Site Scripting                                                                                                                                     | php/webapps/29284.txt
Moodle 1.6dev - SQL Injection / Command Execution                                                                                                                                                          | php/webapps/1312.php
Moodle 1.7.1 - 'index.php' Cross-Site Scripting                                                                                                                                                            | php/webapps/30261.txt
Moodle 1.8.3 - 'install.php' Cross-Site Scripting                                                                                                                                                          | php/webapps/31020.txt
Moodle 1.8.4 - Remote Code Execution                                                                                                                                                                       | php/webapps/6356.php
Moodle 1.9.3 - Remote Code Execution                                                                                                                                                                       | php/webapps/7437.txt
Moodle 1.x - 'post.php' Cross-Site Scripting                                                                                                                                                               | php/webapps/24356.txt
Moodle 2.0.1 - 'PHPCOVERAGE_HOME' Cross-Site Scripting                                                                                                                                                     | php/webapps/35297.txt
Moodle 2.3.8/2.4.5 - Multiple Vulnerabilities                                                                                                                                                              | php/webapps/28174.txt
Moodle 2.5.9/2.6.8/2.7.5/2.8.3 - Block Title Handler Cross-Site Scripting                                                                                                                                  | php/webapps/36418.txt
Moodle 2.7 - Persistent Cross-Site Scripting                                                                                                                                                               | php/webapps/34169.txt
Moodle 2.x/3.x - SQL Injection                                                                                                                                                                             | php/webapps/41828.php
Moodle 3.10.3 - 'label' Persistent Cross Site Scripting                                                                                                                                                    | php/webapps/49714.txt
Moodle 3.10.3 - 'url' Persistent Cross Site Scripting                                                                                                                                                      | php/webapps/49797.txt
Moodle 3.11.4  - SQL Injection                                                                                                                                                                             | php/webapps/50700.txt
Moodle 3.11.5 - SQLi (Authenticated)                                                                                                                                                                       | php/webapps/50825.py
Moodle 3.4.1 - Remote Code Execution                                                                                                                                                                       | php/webapps/46551.php
Moodle 3.6.1 - Persistent Cross-Site Scripting (XSS)                                                                                                                                                       | php/webapps/49814.txt
Moodle 3.6.3 - 'Install Plugin' Remote Command Execution (Metasploit)                                                                                                                                      | php/remote/46775.rb
Moodle 3.8 - Unrestricted File Upload                                                                                                                                                                      | php/webapps/49114.txt
Moodle 3.9 - Remote Code Execution (RCE) (Authenticated)                                                                                                                                                   | php/webapps/50180.py
Moodle < 1.6.9/1.7.7/1.8.9/1.9.5 - File Disclosure                                                                                                                                                         | php/webapps/8297.txt
Moodle Blog 1.18.2.2/1.6.2 Module - SQL Injection                                                                                                                                                          | php/webapps/28770.txt
Moodle Filepicker 3.5.2 - Server Side Request Forgery                                                                                                                                                      | php/webapps/47177.txt
Moodle Help Script 1.x - Cross-Site Scripting                                                                                                                                                              | php/webapps/24279.txt
Moodle Jmol Filter 6.1 - Directory Traversal / Cross-Site Scripting                                                                                                                                        | php/webapps/46881.txt
Moodle LMS 4.0 - Cross-Site Scripting (XSS)                                                                                                                                                                | php/webapps/51115.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


