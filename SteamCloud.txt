SteamCloud IP:10.10.11.133


rustscan:

PORT      STATE SERVICE     REASON
PORT      STATE SERVICE     REASON
22/tcp    open  ssh         syn-ack
2379/tcp  open  etcd-client syn-ack
8443/tcp  open  https-alt   syn-ack
10249/tcp open  unknown     syn-ack
10250/tcp open  unknown     syn-ack
10256/tcp open  unknown     syn-ack


nmap:
PORT      STATE  SERVICE          REASON       VERSION
22/tcp    open   ssh              syn-ack      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCu4TNCZjLe74tZ0HyspkMaghndsvuXkZJa4lJBt9arqgkm6u2HI/RRdwbjE14au2u/YF89y23Q55iOGraA+9JjpyTzDPo3kxE/RisYzJaUDmzza+hqEeyTxXkZby9+DAhKm5UXs7M2CMDr3cwOPPQ96u/zUX0gDG3CfYw4fAi2TDGa6jU5KmGzIQz6SQR3Bv6IYLDwzNJ0nHNZ3jxSbFS3SsmTwK749GJLrv62wAf4uUL/Ihynl8cCG5aor6T0Fk44v/9ndfujznBvWaMYVPpf9B49XlD7OhXB5pCK2nPZrdze+ch6yhAM/vYrYA4sNk3IuFG3OCrDkVeUJn5sJKx5
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHVj7iKnl8SWdGz6J4F3kvpZjM1Tim0iHlUnQByS8xJYnfwttLxVwGb+aaGbRhOJu4mq9y4crwFh50rC9mAEHWo=
|   256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHXIZpU9XbtZ2zvx8rFEYTfGp+8JCJx5lSiRNEcqUFG8
2379/tcp  open   ssl/etcd-client? syn-ack
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Issuer: commonName=etcd-ca
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-02-14T13:47:28
| Not valid after:  2024-02-14T13:47:28
| MD5:   1d20 feed 1b67 c763 9e17 d5b7 ee78 904e
| SHA-1: bc48 266b 9fd1 17f5 17f9 b5d5 8dde 179d 9fe2 2474
| -----BEGIN CERTIFICATE-----
| MIIDSzCCAjOgAwIBAgIIGtEcjscvDMQwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE
| AxMHZXRjZC1jYTAeFw0yMzAyMTQxMzQ3MjhaFw0yNDAyMTQxMzQ3MjhaMBUxEzAR
| BgNVBAMTCnN0ZWFtY2xvdWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
| AQDFzDyfXhMCLdK7Nz4KFniddyW7Zmh2+bHE7T62xS36SQPxP0fDe6AO9PngYO9m
| nZaFgILz4VkduwBu+2f+YMfbOx1PMsP+9VBcZef9DJTuY4y/d+bM+OQM1LYxRgFm
| twLP7Bg9Kjj9xdN5g3V4mbVD2ZD0JeYlid5I8avXeSOz2nJbOW7/dne6KbmNla7c
| wWKCYjWRZNJsNVpc20H6882IambZIQTLwiWAday9aVQRS3SJbInkfQLxJOQWicEl
| a1GRjIcWCdHw8R7vWzA2Bc0nQ6h0QfFF1vlbNmcBy0djOchpb9xr9IiWhYgafAAz
| Ym/gIAlQCAjMaKRl+o4lJSulAgMBAAGjgaEwgZ4wDgYDVR0PAQH/BAQDAgWgMB0G
| A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1Ud
| IwQYMBaAFB/xuf7C6xPm9xzM8PRN+bUG7ImcMD4GA1UdEQQ3MDWCCWxvY2FsaG9z
| dIIKc3RlYW1jbG91ZIcECgoLhYcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkq
| hkiG9w0BAQsFAAOCAQEAVX0DRkNeHIbx/NDGxDiCHgaunXS5O5hm8I6Xrm6Ts/y3
| kU2iFdhr50FYK+HwyjnPr36WTmOSET1AB+Z2nBVc9dIVUGPqMtCFjYqzNGPLERpi
| RRbkLWGwRol7rrkRZIM0yGD3fzw/fUd5WcDVlqY1ACDGYGtk++9cS0E2ZtVr3eKK
| 3swYGlbzgYh20znnrrijTntPhtxtYrNDNWTL/SP9Kpkxvk6qDrV8TKbv1ZlL93lb
| XHyd33YxhpgdfHXB/1cIhqh/tpexhOhhLM8r5hZI1TQfh+zh9KZfAYDHo+HeKJFG
| axDcJQAKiyr2uzmXzauhf+4lKnHxvJxwaO2zSViSfQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
2380/tcp  open   ssl/etcd-server? syn-ack
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Issuer: commonName=etcd-ca
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-02-14T13:47:28
| Not valid after:  2024-02-14T13:47:28
| MD5:   c8cf 177a be68 c378 ee53 6ee9 f91f 62c5
| SHA-1: 2b8c c078 33f8 91fa e72e 2df9 c0b2 efe5 508d 380d
| -----BEGIN CERTIFICATE-----
| MIIDSzCCAjOgAwIBAgIIXO6P4WOFglUwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE
| AxMHZXRjZC1jYTAeFw0yMzAyMTQxMzQ3MjhaFw0yNDAyMTQxMzQ3MjhaMBUxEzAR
| BgNVBAMTCnN0ZWFtY2xvdWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
| AQC6MkKhkOtq+Ge9GE46ioq1LpATK+BCbFbysn/I0o5n44HnLRpkCXnnXxwx6Ive
| 4siNVs82Z/opSeRqEqRledGY0FhTYSWebMpszUmo4jsHGjOjImbFVHPYNFYZY/V8
| xoZrkW39Ae847BpzW3zSOPYoz/n7l7fWWWbc/ECFt1RKvKZUeHOhAWmD6rV9WMVr
| DnvTc7kgHF7kFnp4fdisr/ZhIsPonl9pqnVquREDCFkokdjcT/eyLeDN/ylUjusy
| jLI8gCfw/+Yhy6r8r614utSjnY0IC7oIaBwzUxkHz09TMBPwz/Ps7N/iGUzSzv4t
| Y9xWE8xtlqgtfYH8bJSAeiAFAgMBAAGjgaEwgZ4wDgYDVR0PAQH/BAQDAgWgMB0G
| A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1Ud
| IwQYMBaAFB/xuf7C6xPm9xzM8PRN+bUG7ImcMD4GA1UdEQQ3MDWCCWxvY2FsaG9z
| dIIKc3RlYW1jbG91ZIcECgoLhYcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkq
| hkiG9w0BAQsFAAOCAQEAnAWSHRmvlEZhZr1dwQgi5X6jutbrybqMzKODlFSQkqAx
| kKfZaJKEazgpFso1682RZzQ19rW72+MfRB7dRXvpu8wcrl0jg8Tx/+Cnzg7xttnj
| MiMhh92CTZP/dnWiCjHIO8aRsUmwCgLCf7raIpBHnJtNDZQ82q4LnAV2kd5nZwN4
| 4y8TKV2Qlj/g4XUrz8THrrOxmCLNRDevFt2b9OS5aWHjU525fEvVq5nSN42y5ZUB
| NDYmGZR3KXQ016IRVZMx0CM6xjr5k2xhe5laM4lRC3mKPto4tALuM83HCFKqGN5c
| GTQRN0mdbtEi88uFqiV2zl1tIzkN1b5+IHxSD2m/oA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
8433/tcp  closed unknown          conn-refused
10249/tcp open   http             syn-ack      Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open   ssl/http         syn-ack      Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=steamcloud@1676382451
| Subject Alternative Name: DNS:steamcloud
| Issuer: commonName=steamcloud-ca@1676382450
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-02-14T12:47:30
| Not valid after:  2024-02-14T12:47:30
| MD5:   9a75 b752 d8f5 db4b 8ab2 937a 5e48 ce14
| SHA-1: 6c13 4eda 6792 d3c4 ef26 9303 1c4a 0990 aed7 d3e6
| -----BEGIN CERTIFICATE-----
| MIIDKzCCAhOgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDDBhzdGVh
| bWNsb3VkLWNhQDE2NzYzODI0NTAwHhcNMjMwMjE0MTI0NzMwWhcNMjQwMjE0MTI0
| NzMwWjAgMR4wHAYDVQQDDBVzdGVhbWNsb3VkQDE2NzYzODI0NTEwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWbrwclNvIGI26zm9tssM7ydPSwoGEN0iA
| Z/5oomnQZD/ETBE43ivTO8j2SWVw4lPdNDlsgILHviv3Mu4R4sx1WBZh623/joZZ
| J6CeUJw7OYtTGge8ch86i5HO+RE9EUlcmmgFEijqiQrdgDx5RN+rcemeYs+0HiK1
| McSq9daW2/PkMMcG0+1g939VDDWYuSqamwVjDUvzStDVG2CgzD4Hqp+bSZSK5RbA
| i46rK8+Bg7xogdR5fdOcmck1rfph8ASwojsPKJguiSgo031g5akCsm/HGQyG5DCz
| qzKwI0dj02W0njSjkO8Ypad0DQhajsx6lXTkQWfDbyEpsVujB4fdAgMBAAGjbTBr
| MA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8E
| AjAAMB8GA1UdIwQYMBaAFIfYGWZMtvmbyGyKuU/nZ2EQ34P8MBUGA1UdEQQOMAyC
| CnN0ZWFtY2xvdWQwDQYJKoZIhvcNAQELBQADggEBAGWkyF/xUZjGlNVV8EFmfYq9
| 45oPw6LhgG6XFEUsHE+L0Ng2uCKP7PUm+jLnJjkq/JfPx8Z4YGrgnnMvDYs1k+E7
| eCY8QJNPA56B4CsL+rMGTY82VVHOpMKF6IDNF3cIPmyBuyFo/l/mnEgEkACxQYpe
| +WAr1bU6NOB220SXMvUcpr1zFXI6WrB2b5AAtlSM5mHkLg5hYoGpDLQ2B5uthFau
| UiJJGK9Bpxl5c7axvabLbdO7LOpy9XODoKZZCVq1kyW1BabSEpVA6yWUKZBrK5NL
| X6LczXrlFZJKfVMuYBD2Vqi6HnoGVqSSNnPAWe7GNH6GRTAR3lU4my5fSrN+peY=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10256/tcp open   http             syn-ack      Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
