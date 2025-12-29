package cert

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
)

// FormatDN formats a pkix.Name as a readable string
func FormatDN(n pkix.Name) string {
	var parts []string
	if n.CommonName != "" {
		parts = append(parts, "CN="+n.CommonName)
	}
	if len(n.Organization) > 0 {
		parts = append(parts, "O="+strings.Join(n.Organization, ","))
	}
	if len(n.OrganizationalUnit) > 0 {
		parts = append(parts, "OU="+strings.Join(n.OrganizationalUnit, ","))
	}
	if len(n.Country) > 0 {
		parts = append(parts, "C="+strings.Join(n.Country, ","))
	}
	if len(n.Locality) > 0 {
		parts = append(parts, "L="+strings.Join(n.Locality, ","))
	}
	if len(n.Province) > 0 {
		parts = append(parts, "ST="+strings.Join(n.Province, ","))
	}
	if len(parts) == 0 {
		return n.String()
	}
	return strings.Join(parts, ", ")
}

// TLSVersion converts TLS version constant to string
func TLSVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

// PublicKeySummary returns a readable description of the public key
func PublicKeySummary(c *x509.Certificate) string {
	switch pk := c.PublicKey.(type) {
	case interface{ Size() int }:
		return fmt.Sprintf("%T (%d bits)", c.PublicKey, pk.Size()*8)
	default:
		return fmt.Sprintf("%T", c.PublicKey)
	}
}

// ExtKeyUsageToString converts ExtKeyUsage to string
func ExtKeyUsageToString(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSECEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSECTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSECUser"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "MicrosoftSGC"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "NetscapeSGC"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "MicrosoftCommercialCodeSigning"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "MicrosoftKernelCodeSigning"
	default:
		return fmt.Sprintf("Unknown(%d)", int(u))
	}
}

// ColorBool returns a colored string for boolean values
func ColorBool(ok bool) string {
	const (
		green = "\x1b[32m"
		red   = "\x1b[31m"
		reset = "\x1b[0m"
	)
	if ok {
		return green + "TRUE" + reset
	}
	return red + "FALSE" + reset
}
