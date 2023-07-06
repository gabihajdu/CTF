Preignition IP:10.129.158.56

rustscan:

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack



nmap:

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Welcome to nginx!



gobuster:

gobuster dir -u 10.129.158.56 -w /usr/share/wordlists/dirb/common.txt -t 64 -x txt,php,html
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.158.56
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,php,html
[+] Timeout:                 10s
===============================================================
2023/04/25 14:42:39 Starting gobuster in directory enumeration mode
===============================================================
/admin.php            (Status: 200) [Size: 999]
/admin.php            (Status: 200) [Size: 999]
Progress: 17953 / 18460 (97.25%)
===============================================================
2023/04/25 14:42:58 Finished
===============================================================
