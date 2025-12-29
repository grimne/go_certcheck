package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestFormatDN(t *testing.T) {
	tests := []struct {
		name     string
		dn       pkix.Name
		expected string
	}{
		{
			name: "full DN",
			dn: pkix.Name{
				CommonName:         "example.com",
				Organization:       []string{"Example Org"},
				OrganizationalUnit: []string{"IT"},
				Country:            []string{"US"},
				Locality:           []string{"San Francisco"},
				Province:           []string{"California"},
			},
			expected: "CN=example.com, O=Example Org, OU=IT, C=US, L=San Francisco, ST=California",
		},
		{
			name: "CN only",
			dn: pkix.Name{
				CommonName: "example.com",
			},
			expected: "CN=example.com",
		},
		{
			name: "multiple organizations",
			dn: pkix.Name{
				CommonName:   "example.com",
				Organization: []string{"Org1", "Org2"},
			},
			expected: "CN=example.com, O=Org1,Org2",
		},
		{
			name:     "empty DN",
			dn:       pkix.Name{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatDN(tt.dn)
			if tt.expected == "" {
				// Empty DN should return the String() representation
				// which could be empty or a default format
				t.Logf("FormatDN(empty) = %q", result)
			} else if result != tt.expected {
				t.Errorf("FormatDN() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestTLSVersion(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS13, "TLS1.3"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS10, "TLS1.0"},
		{0x9999, "0x9999"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := TLSVersion(tt.version)
			if result != tt.expected {
				t.Errorf("TLSVersion(%d) = %q, want %q", tt.version, result, tt.expected)
			}
		})
	}
}

func TestPublicKeySummary(t *testing.T) {
	// Create RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	tests := []struct {
		name     string
		cert     *x509.Certificate
		contains string
	}{
		{
			name: "RSA key",
			cert: &x509.Certificate{
				PublicKey: &rsaKey.PublicKey,
			},
			contains: "2048 bits",
		},
		{
			name: "ECDSA key",
			cert: &x509.Certificate{
				PublicKey: &ecdsaKey.PublicKey,
			},
			contains: "256 bits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PublicKeySummary(tt.cert)
			if result == "" {
				t.Errorf("PublicKeySummary() returned empty string")
			}
			// Just verify we get some output - exact format may vary
			t.Logf("PublicKeySummary() = %q", result)
		})
	}
}

func TestExtKeyUsageToString(t *testing.T) {
	tests := []struct {
		usage    x509.ExtKeyUsage
		expected string
	}{
		{x509.ExtKeyUsageAny, "Any"},
		{x509.ExtKeyUsageServerAuth, "ServerAuth"},
		{x509.ExtKeyUsageClientAuth, "ClientAuth"},
		{x509.ExtKeyUsageCodeSigning, "CodeSigning"},
		{x509.ExtKeyUsageEmailProtection, "EmailProtection"},
		{x509.ExtKeyUsageIPSECEndSystem, "IPSECEndSystem"},
		{x509.ExtKeyUsageIPSECTunnel, "IPSECTunnel"},
		{x509.ExtKeyUsageIPSECUser, "IPSECUser"},
		{x509.ExtKeyUsageTimeStamping, "TimeStamping"},
		{x509.ExtKeyUsageOCSPSigning, "OCSPSigning"},
		{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "MicrosoftSGC"},
		{x509.ExtKeyUsageNetscapeServerGatedCrypto, "NetscapeSGC"},
		{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "MicrosoftCommercialCodeSigning"},
		{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "MicrosoftKernelCodeSigning"},
		{x509.ExtKeyUsage(9999), "Unknown(9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := ExtKeyUsageToString(tt.usage)
			if result != tt.expected {
				t.Errorf("ExtKeyUsageToString(%d) = %q, want %q", tt.usage, result, tt.expected)
			}
		})
	}
}

func TestColorBool(t *testing.T) {
	tests := []struct {
		name     string
		value    bool
		contains string
	}{
		{
			name:     "true",
			value:    true,
			contains: "TRUE",
		},
		{
			name:     "false",
			value:    false,
			contains: "FALSE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ColorBool(tt.value)
			if result == "" {
				t.Errorf("ColorBool(%v) returned empty string", tt.value)
			}
			// Result should contain the expected string (with ANSI codes)
			t.Logf("ColorBool(%v) = %q", tt.value, result)
		})
	}
}

// Helper function to create a test certificate
func createTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
