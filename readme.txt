Synced IP:10.129.210.169



rustscan:

PORT    STATE SERVICE REASON
873/tcp open  rsync   syn-ack


nmap:

PORT    STATE SERVICE REASON  VERSION
873/tcp open  rsync   syn-ack (protocol version 31)

 rsync --list-only rsync://10.129.210.169
public         	Anonymous Share


rsync --list-only rsync://10.129.210.169/public
drwxr-xr-x          4,096 2022/10/25 01:02:23 .
-rw-r--r--             33 2022/10/25 00:32:03 flag.txt

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Synced]
└─$ rsync --list-only rsync://10.129.210.169/public/flag.txt
-rw-r--r--             33 2022/10/25 00:32:03 flag.txt

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Synced]
└─$ rsync  rsync://10.129.210.169/public/flag.txt .

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Synced]
└─$ cat flag.txt 
72eaf5344ebb84908ae543a719830519

