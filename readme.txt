Ingition IP:10.129.241.189


rustscam:
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack



nmap:


PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack nginx 1.14.2
|_http-title: Home page
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-favicon: Unknown favicon MD5: 643D3106699AA425269DBE0BB7768440
|_http-server-header: nginx/1.14.2

gobuster:

/media                (Status: 301) [Size: 185] [--> http://ignition.htb/media/]
/contact              (Status: 200) [Size: 28673]
/home                 (Status: 200) [Size: 25802]
/0                    (Status: 200) [Size: 25803]
/static               (Status: 301) [Size: 185] [--> http://ignition.htb/static/]
/catalog              (Status: 302) [Size: 0] [--> http://ignition.htb/]
/admin                (Status: 200) [Size: 7095]
/Home                 (Status: 301) [Size: 0] [--> http://ignition.htb/home]
