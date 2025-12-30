# CertCheck

A fast, modern TLS/SSL certificate inspection tool with support for direct TLS connections and StartTLS protocols.

## Features

**Direct TLS connections** (HTTPS, IMAPS, etc.)  
**StartTLS support** for SMTP, IMAP, POP3 and FTP  
**Multiple output formats**: text, JSON, YAML, TOML  
**Certificate chain inspection**  
**Certificate verification** against system trust store  
**Expiry checking** with days-until-expiry  
**SNI support** for virtual hosting  

## Quick Start Build Instructions

### 1. Initialize Project

```bash
# Initialize Go module
go mod init github.com/grimne/certcheck

# Download dependencies
go get github.com/BurntSushi/toml@v1.3.2
go get gopkg.in/yaml.v3@v3.0.1
go mod tidy
```

## Installation

### From Source

```bash
git clone https://github.com/grimne/certcheck.git
cd certcheck
make build
```

### Using Go Install

```bash
go install github.com/grimne/certcheck/cmd/certcheck@latest
```

## Usage

### Basic Examples

```bash
# Check HTTPS certificate
certcheck example.com

# Check with specific port
certcheck example.com:443

# Check with custom SNI
certcheck -sni www.example.com 1.2.3.4

# JSON output
certcheck -o json example.com

# YAML output
certcheck -o yaml example.com
```

### StartTLS Examples

```bash
# Check SMTP server
certcheck -starttls smtp mail.example.com:25

# Check IMAP server (uses default port 143)
certcheck -starttls imap mail.example.com

# Check POP3 server
certcheck -starttls pop3 mail.example.com:110

# Check FTP server with AUTH TLS
certcheck -starttls ftp ftp.example.com:21
```

### Advanced Examples

```bash
# JSON output with SMTP StartTLS
certcheck -starttls smtp -o json mail.example.com

# Check with timeout
certcheck -timeout 15s slow-server.com

# Without certificate chain
certcheck -chain=false example.com

# Pipe JSON to jq for filtering
certcheck -o json example.com | jq '.leaf.dns_names'
```

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-sni` | hostname | SNI / ServerName override |
| `-timeout` | 10s | Connection timeout |
| `-starttls` | none | StartTLS protocol (smtp\|imap\|pop3\|ftp) |
| `-chain` | true | Include certificate chain in output |
| `-o` | text | Output format (text\|json\|yaml\|toml) |

## Output Formats

### Text (default)
Human-readable format with colors

### JSON
```json
{
  "connection": {
    "target": "example.com:443",
    "tls_version": "TLS1.3",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "sni": "example.com",
    "verified": true
  },
  "leaf": {
    "subject": "CN=example.com",
    "issuer": "CN=Example CA",
    ...
  },
  "expiry": {
    "not_after": "2025-12-31T23:59:59Z",
    "days_left": 365
  }
}
```

### YAML
```yaml
connection:
  target: example.com:443
  tls_version: TLS1.3
  verified: true
leaf:
  subject: CN=example.com
  dns_names:
    - example.com
    - www.example.com
```

### TOML
```toml
[connection]
target = "example.com:443"
tls_version = "TLS1.3"
verified = true

[leaf]
subject = "CN=example.com"
dns_names = ["example.com", "www.example.com"]
```

## Building

### Prerequisites
- Go 1.21 or later

### Build Commands

```bash
# Development build
make build

# Production build (optimized)
make release

# Cross-compile for all platforms
make build-all

# Run tests
make test

# Clean build artifacts
make clean

# Install to $GOPATH/bin
make install
```

## Supported StartTLS Protocols

- **SMTP** (port 25, 587) - Email submission
- **IMAP** (port 143) - Email retrieval
- **POP3** (port 110) - Email retrieval
- **FTP** (port 21) - File transfer with AUTH TLS

## Exit Codes

- `0` - Success
- `1` - Connection or certificate error
- `2` - Invalid arguments or configuration

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or pull request.

## Credit
Claude
