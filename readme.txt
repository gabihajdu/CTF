Validation IP:10.10.11.116


rustscan:
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
80/tcp   open  http       syn-ack
8080/tcp open  http-proxy syn-ack
4566/tcp open  kwtc       syn-ack




nmap:
PORT     STATE    SERVICE        REASON      VERSION
22/tcp   open     ssh            syn-ack     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgSpafkjRVogAlgtxt6cFN7sU4sRTiGYC01QloBpbOwerqFUoYNyhCdNP/9rvdhwFpXomoMhDxioWQZb1RTSbR5aCwkzwDRnLz5PKN/7faaoEVjFM1vSnjGwWxzPZJw4Xy8wEbvMDlNZQbWu44UMWhLH+Vp63egRsut0SkTpUy3Ovp/yb3uAeT/4sUPG+LvDgzXD2QY+O1SV0Y3pE+pRmL3UfRKr2ltMfpcc7y7423+3oRSONHfy1upVUcUZkRIKrl9Qb4CDpxbVi/hYfAFQcOYH+IawAounkeiTMMEtOYbzDysEzVrFcCiGPWOX5+7tu4H7jYnZiel39ka/TFODVA+m2ZJiz2NoKLKTVhouVAGkH7adYtotM62JEtow8MW0HCZ9+cX6ki5cFK9WQhN++KZej2fEZDkxV7913KaIa4HCbiDq1Sfr5j7tFAWnNDo097UHXgN5A0mL1zNqwfTBCHQTEga/ztpDE0pmTKS4rkBne9EDn6GpVhSuabX9S/BLk=
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9LolyD5tnJ06EqjRR6bFX/7oOoTeFPw2TKsP1KCHJcsPSVfZIafOYEsWkaq67dsCvOdIZ8VQiNAKfnGiaBLOo=
|   256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOP8cvEQVqCwuWYT06t/DEGxy6sNajp7CzuvfJzrCRZ
80/tcp   open     http           syn-ack     Apache httpd 2.4.48 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
4566/tcp open     http           syn-ack     nginx
|_http-title: 403 Forbidden
5000/tcp filtered upnp           no-response
5001/tcp filtered commplex-link  no-response
5002/tcp filtered rfe            no-response
5003/tcp filtered filemaker      no-response
5004/tcp filtered avt-profile-1  no-response
5005/tcp filtered avt-profile-2  no-response
5006/tcp filtered wsm-server     no-response
5007/tcp filtered wsm-server-ssl no-response
5008/tcp filtered synapsis-edge  no-response
8080/tcp open     http           syn-ack     nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


gobuster dir  -u http://10.10.11.116  -w /usr/share/wordlists/dirb/common.txt -t 64  -x php,txt,html
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.11.116
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php,txt
[+] Timeout:        10s
===============================================================
2023/02/17 04:01:56 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.html (Status: 403)
/.hta (Status: 403)
/.hta.html (Status: 403)
/.hta.php (Status: 403)
/.hta.txt (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.html (Status: 403)
/account.php (Status: 200)
/config.php (Status: 200)
/css (Status: 301)
/index.php (Status: 200)
/index.php (Status: 200)
/js (Status: 301)
/server-status (Status: 403)
===============================================================
2023/02/17 04:02:12 Finished
===============================================================





Navigating to port 80 reveals a single page that asks for a username and a dropdown box to
select the country. If this request is intercepted we can see that the dropdown is just plaintext
and we can modify it to be values other than a country. Additionally, the page will send us a
cookie back called "user" and direct us to /account.php. If we send this request multiple times, we
will notice the cookie it is giving us does not change until we change the "Username" variable
indicating that the session is not random.

Upon registering an account we are brought to a page that shows other players in our country. If
we edit the registration request and place a Single Quote in the country the account page will
display an error message:
: Uncaught Error: Call to a member function fetch_assoc() on bool in
/var/www/html/account.php:33


