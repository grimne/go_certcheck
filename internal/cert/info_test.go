package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestBuildCertificate(t *testing.T) {
	// Create a test certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	testURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"example.com", "www.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.0.2.1")},
		EmailAddresses:        []string{"admin@example.com"},
		URIs:                  []*url.URL{testURL},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Build Certificate struct
	result := BuildCertificate(cert)

	// Verify basic fields
	if result.Subject == "" {
		t.Error("Subject should not be empty")
	}
	if result.Issuer == "" {
		t.Error("Issuer should not be empty")
	}
	if result.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}
	if result.NotBefore == "" {
		t.Error("NotBefore should not be empty")
	}
	if result.NotAfter == "" {
		t.Error("NotAfter should not be empty")
	}
	if result.SignatureAlgo == "" {
		t.Error("SignatureAlgo should not be empty")
	}
	if result.PublicKey == "" {
		t.Error("PublicKey should not be empty")
	}

	// Verify DNS names
	if len(result.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(result.DNSNames))
	}

	// Verify IP addresses
	if len(result.IPAddresses) != 1 {
		t.Errorf("expected 1 IP address, got %d", len(result.IPAddresses))
	}

	// Verify email addresses
	if len(result.EmailAddresses) != 1 {
		t.Errorf("expected 1 email address, got %d", len(result.EmailAddresses))
	}

	// Verify URIs
	if len(result.URIs) != 1 {
		t.Errorf("expected 1 URI, got %d", len(result.URIs))
	}

	// Verify ExtKeyUsage
	if len(result.ExtKeyUsage) != 2 {
		t.Errorf("expected 2 ExtKeyUsage values, got %d", len(result.ExtKeyUsage))
	}

	// Verify IsCA
	if result.IsCA {
		t.Error("expected IsCA to be false")
	}
}

func TestBuildCertificateMinimal(t *testing.T) {
	// Create a minimal certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
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

	result := BuildCertificate(cert)

	// Verify that empty slices are handled correctly
	if len(result.DNSNames) > 0 {
		t.Error("DNSNames should be empty or nil")
	}
	if len(result.IPAddresses) > 0 {
		t.Error("IPAddresses should be empty or nil")
	}
	if len(result.EmailAddresses) > 0 {
		t.Error("EmailAddresses should be empty or nil")
	}
	if len(result.URIs) > 0 {
		t.Error("URIs should be empty or nil")
	}
	if len(result.ExtKeyUsage) > 0 {
		t.Error("ExtKeyUsage should be empty or nil")
	}
}

func TestBuildExpiryInfo(t *testing.T) {
	tests := []struct {
		name         string
		notAfter     time.Time
		expectedDays int
	}{
		{
			name:         "expires in 30 days",
			notAfter:     time.Now().Add(30 * 24 * time.Hour),
			expectedDays: 30,
		},
		{
			name:         "expires in 1 day",
			notAfter:     time.Now().Add(24 * time.Hour),
			expectedDays: 1,
		},
		{
			name:         "expired 10 days ago",
			notAfter:     time.Now().Add(-10 * 24 * time.Hour),
			expectedDays: -10,
		},
		{
			name:         "expires in 365 days",
			notAfter:     time.Now().Add(365 * 24 * time.Hour),
			expectedDays: 365,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotAfter: tt.notAfter,
			}

			result := BuildExpiryInfo(cert)

			if result.NotAfter == "" {
				t.Error("NotAfter should not be empty")
			}

			// Allow for +/- 1 day difference due to timing
			if result.DaysLeft < tt.expectedDays-1 || result.DaysLeft > tt.expectedDays+1 {
				t.Errorf("expected DaysLeft to be around %d, got %d", tt.expectedDays, result.DaysLeft)
			}
		})
	}
}

func TestBuildCertificateCA(t *testing.T) {
	// Create a CA certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	result := BuildCertificate(cert)

	if !result.IsCA {
		t.Error("expected IsCA to be true")
	}
}
