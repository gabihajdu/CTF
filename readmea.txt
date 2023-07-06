Explosion IP:10.129.164.22


rustscan:
PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
3389/tcp  open  ms-wbt-server syn-ack
5985/tcp  open  wsman         syn-ack
49664/tcp open  unknown       syn-ack
49665/tcp open  unknown       syn-ack
49666/tcp open  unknown       syn-ack
49667/tcp open  unknown       syn-ack
49668/tcp open  unknown       syn-ack
49669/tcp open  unknown       syn-ack
49670/tcp open  unknown       syn-ack
49671/tcp open  unknown       syn-ack



nmap:

PORT      STATE SERVICE       REASON  VERSION
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
|_ssl-date: 2023-04-21T13:39:16+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=Explosion
| Issuer: commonName=Explosion
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-04-20T13:33:40
| Not valid after:  2023-10-20T13:33:40
| MD5:   51ae1e1369a568012048c7c3cab6fda3
| SHA-1: 9f718037354860e2da22afe9c0d5b333e371d986
| -----BEGIN CERTIFICATE-----
| MIIC1jCCAb6gAwIBAgIQWnATJbysGZtPtHzsO9YQfTANBgkqhkiG9w0BAQsFADAU
| MRIwEAYDVQQDEwlFeHBsb3Npb24wHhcNMjMwNDIwMTMzMzQwWhcNMjMxMDIwMTMz
| MzQwWjAUMRIwEAYDVQQDEwlFeHBsb3Npb24wggEiMA0GCSqGSIb3DQEBAQUAA4IB
| DwAwggEKAoIBAQDA/5enWpBP4jhdGbXYnYPur1kh8He3ihKmimJsXHu/gUdIR4Pe
| o7Z6Rn4H4dNMqFRva9R0/0srWdvamjmJ2cC8Kr8U3O0rrK9xqi5tZBMGkEFczEbu
| opE7aHdJK6s44MBGaF6Q2zNBDfA8ake4+MqvsI4dEyUp97y/yHvD4pgmulFeFQlS
| zjGXCXbs4CkjRV/af8n5dWLg8KtFMgkKYXLu8mV3Mm4RA3Ydh8pdXK5rL/ADZP0B
| 8BVOEotRxLlg9JXUji6SZM2BGHrvta8vDSSpvaea48GLk7BKsf14se1684FTxtl2
| 5gFmTlhs4uUokDd/PAJbbE3+83SS4dFdpQIRAgMBAAGjJDAiMBMGA1UdJQQMMAoG
| CCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEACxUCc1De
| BoLSeFb+rIFFRY+Asz5YpngmBYyLU7bUWAlireOoS64HFMu8d0yvM/gCFlnb1pQn
| zG2DGoDULcUxzAK74DwBF1z4TI1SG9A0ZjOztOSOoLS1caVgqsVKk+xjx0DcbT3l
| ZQ5hf4saWAGTckwIYKZETHNd5xFVOzERktebzeYGVT9If7Yt+snvkJKvgTXoGRkg
| Yt8qmaRhgEjTeXmJXeEWA5gLGeXBqqJ242OCcJpXI26fREYQ2Sy9Pe2VY2/LfyhC
| X4Wj7iBi3NC0XDAxgJKRyPg4wSC0dfsr+1Eid2weTc4h82Hoc/MqVev2Ut99vTYl
| OsIKbXH+0zS1ig==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: EXPLOSION
|   NetBIOS_Domain_Name: EXPLOSION
|   NetBIOS_Computer_Name: EXPLOSION
|   DNS_Domain_Name: Explosion
|   DNS_Computer_Name: Explosion
|   Product_Version: 10.0.17763
|_  System_Time: 2023-04-21T13:39:05+00:00
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
|_smb2-time: ERROR: Script execution failed (use -d to debug)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 9974/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 36949/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 10167/udp): CLEAN (Timeout)
|   Check 4 (port 27309/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!


connect to xfreerdp /v: ip /u:Administrator .YOu can connect without a passwd

Flag:

951fa96d7830c451b536be5a6be008a0