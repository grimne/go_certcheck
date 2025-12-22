# go_certcheck

Credits to ChatGPT :robot:

A small, single-binary Go tool that connects to any TLS endpoint and prints
browser-like certificate information.

Works with HTTPS, SMTPS, IMAPS, LDAPs, or any service that speaks TLS.
No dependencies. One binary. Inspect everything.


## Features
- Connects to any TLS endpoint
- Assumes port 443 if none is specified
- Supports SNI override
- Always retrieves certificates (even broken ones)
- Verifies the certificate chain separately and reports:
  - TRUE (green) if valid
  - FALSE (red) if invalid
- Prints:
  - Subject / Issuer
  - SANs (DNS, IP, email, URI)
  - Validity dates + days remaining
  - Signature algorithm
  - Public key type and size
  - Certificate chain (as presented)

## Build
```
go build -o certcheck
```

## Usage
```
certcheck [flags] target
```

## Examples
```
certcheck example.com
certcheck example.com:8443
certcheck mail.example.com:465
certcheck -sni www.example.com 1.2.3.4
certcheck [2001:db8::1]
```

## Flags
```
-sni string
    SNI / ServerName override (default: host from target)

-timeout duration
    Dial timeout (default: 5s)

-chain
    Print peer certificate chain (default: true)

-starttls string
    Yet to be implemented (smtp|imap|pop3)
```
