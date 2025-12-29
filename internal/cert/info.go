package cert

import (
	"crypto/x509"
	"time"
)

// Info holds all certificate information
type Info struct {
	Connection ConnectionInfo `json:"connection" yaml:"connection" toml:"connection"`
	Leaf       Certificate    `json:"leaf" yaml:"leaf" toml:"leaf"`
	Chain      []ChainEntry   `json:"chain,omitempty" yaml:"chain,omitempty" toml:"chain,omitempty"`
	Expiry     ExpiryInfo     `json:"expiry" yaml:"expiry" toml:"expiry"`
}

// ConnectionInfo holds TLS connection details
type ConnectionInfo struct {
	Target      string `json:"target" yaml:"target" toml:"target"`
	TLSVersion  string `json:"tls_version" yaml:"tls_version" toml:"tls_version"`
	CipherSuite string `json:"cipher_suite" yaml:"cipher_suite" toml:"cipher_suite"`
	SNI         string `json:"sni" yaml:"sni" toml:"sni"`
	Verified    bool   `json:"verified" yaml:"verified" toml:"verified"`
	VerifyError string `json:"verify_error,omitempty" yaml:"verify_error,omitempty" toml:"verify_error,omitempty"`
	Protocol    string `json:"protocol,omitempty" yaml:"protocol,omitempty" toml:"protocol,omitempty"`
}

// Certificate holds certificate details
type Certificate struct {
	Subject          string   `json:"subject" yaml:"subject" toml:"subject"`
	Issuer           string   `json:"issuer" yaml:"issuer" toml:"issuer"`
	SerialNumber     string   `json:"serial_number" yaml:"serial_number" toml:"serial_number"`
	NotBefore        string   `json:"not_before" yaml:"not_before" toml:"not_before"`
	NotAfter         string   `json:"not_after" yaml:"not_after" toml:"not_after"`
	SignatureAlgo    string   `json:"signature_algorithm" yaml:"signature_algorithm" toml:"signature_algorithm"`
	PublicKey        string   `json:"public_key" yaml:"public_key" toml:"public_key"`
	DNSNames         []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty" toml:"dns_names,omitempty"`
	IPAddresses      []string `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty" toml:"ip_addresses,omitempty"`
	EmailAddresses   []string `json:"email_addresses,omitempty" yaml:"email_addresses,omitempty" toml:"email_addresses,omitempty"`
	URIs             []string `json:"uris,omitempty" yaml:"uris,omitempty" toml:"uris,omitempty"`
	IsCA             bool     `json:"is_ca" yaml:"is_ca" toml:"is_ca"`
	ExtKeyUsage      []string `json:"ext_key_usage,omitempty" yaml:"ext_key_usage,omitempty" toml:"ext_key_usage,omitempty"`
}

// ChainEntry represents a certificate in the chain
type ChainEntry struct {
	Index   int    `json:"index" yaml:"index" toml:"index"`
	Subject string `json:"subject" yaml:"subject" toml:"subject"`
	Issuer  string `json:"issuer" yaml:"issuer" toml:"issuer"`
}

// ExpiryInfo holds certificate expiry details
type ExpiryInfo struct {
	NotAfter string `json:"not_after" yaml:"not_after" toml:"not_after"`
	DaysLeft int    `json:"days_left" yaml:"days_left" toml:"days_left"`
}

// BuildCertificate converts x509.Certificate to Certificate
func BuildCertificate(cert *x509.Certificate) Certificate {
	c := Certificate{
		Subject:        FormatDN(cert.Subject),
		Issuer:         FormatDN(cert.Issuer),
		SerialNumber:   cert.SerialNumber.Text(16),
		NotBefore:      cert.NotBefore.Format(time.RFC3339),
		NotAfter:       cert.NotAfter.Format(time.RFC3339),
		SignatureAlgo:  cert.SignatureAlgorithm.String(),
		PublicKey:      PublicKeySummary(cert),
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		IsCA:           cert.IsCA,
	}

	if len(cert.IPAddresses) > 0 {
		c.IPAddresses = make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			c.IPAddresses[i] = ip.String()
		}
	}

	if len(cert.URIs) > 0 {
		c.URIs = make([]string, len(cert.URIs))
		for i, uri := range cert.URIs {
			c.URIs[i] = uri.String()
		}
	}

	if len(cert.ExtKeyUsage) > 0 {
		c.ExtKeyUsage = make([]string, len(cert.ExtKeyUsage))
		for i, usage := range cert.ExtKeyUsage {
			c.ExtKeyUsage[i] = ExtKeyUsageToString(usage)
		}
	}

	return c
}

// BuildExpiryInfo creates ExpiryInfo from certificate
func BuildExpiryInfo(cert *x509.Certificate) ExpiryInfo {
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return ExpiryInfo{
		NotAfter: cert.NotAfter.Format(time.RFC3339),
		DaysLeft: daysLeft,
	}
}
