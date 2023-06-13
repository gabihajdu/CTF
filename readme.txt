ip:10.129.95.234

rustscan:
PORT     STATE SERVICE   REASON
80/tcp   open  http      syn-ack
5985/tcp open  wsman     syn-ack
7680/tcp open  pando-pub syn-ack

nmap:
PORT     STATE SERVICE    REASON  VERSION
80/tcp   open  http       syn-ack Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: Unika
5985/tcp open  http       syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp open  pando-pub? syn-ack
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


gobuster:
gobuster dir  -u http://unika.htb -w /usr/share/wordlists/dirb/common.txt  -x php,txt,html
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://unika.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,html
[+] Timeout:        10s
===============================================================
2023/01/05 09:58:41 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.php (Status: 403)
/.hta.txt (Status: 403)
/.hta.html (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.html (Status: 403)
/.htpasswd.php (Status: 403)
/aux (Status: 403)
/aux.php (Status: 403)
/aux.txt (Status: 403)
/aux.html (Status: 403)
/cgi-bin/ (Status: 403)
/cgi-bin/.html (Status: 403)
/com2 (Status: 403)
/com2.html (Status: 403)
/com1 (Status: 403)
/com1.php (Status: 403)
/com1.txt (Status: 403)
/com2.php (Status: 403)
/com2.txt (Status: 403)
/com1.html (Status: 403)
/com3 (Status: 403)
/com3.php (Status: 403)
/com3.txt (Status: 403)
/com3.html (Status: 403)
/con (Status: 403)
/con.txt (Status: 403)
/con.html (Status: 403)
/con.php (Status: 403)
/css (Status: 301)
/english.html (Status: 200)
/English.html (Status: 200)
/french.html (Status: 200)
/german.html (Status: 200)
/img (Status: 301)
/inc (Status: 301)
/Index.php (Status: 200)
/index.php (Status: 200)
/index.php (Status: 200)
/js (Status: 301)
/licenses (Status: 403)
/lpt1 (Status: 403)
/lpt1.php (Status: 403)
/lpt1.txt (Status: 403)
/lpt1.html (Status: 403)
/lpt2 (Status: 403)
/lpt2.html (Status: 403)
/lpt2.php (Status: 403)
/lpt2.txt (Status: 403)
/nul (Status: 403)
/nul.php (Status: 403)
/nul.txt (Status: 403)
/nul.html (Status: 403)
/phpmyadmin (Status: 403)
/prn (Status: 403)
/prn.php (Status: 403)
/prn.txt (Status: 403)
/prn.html (Status: 403)
/server-info (Status: 403)
/server-status (Status: 403)
/webalizer (Status: 403)
===============================================================
2023/01/05 10:00:47 Finished
===============================================================
                                                                
                                                                