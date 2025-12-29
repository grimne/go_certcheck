package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/grimne/certcheck/internal/cert"
	"github.com/grimne/certcheck/internal/config"
	"gopkg.in/yaml.v3"
)

// Helper function to create test certificate info
func createTestCertInfo() *cert.Info {
	return &cert.Info{
		Connection: cert.ConnectionInfo{
			Target:      "example.com:443",
			TLSVersion:  "TLS1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
			SNI:         "example.com",
			Verified:    true,
		},
		Leaf: cert.Certificate{
			Subject:       "CN=example.com",
			Issuer:        "CN=Example CA",
			SerialNumber:  "12345",
			NotBefore:     time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
			NotAfter:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
			SignatureAlgo: "SHA256-RSA",
			PublicKey:     "RSA (2048 bits)",
			DNSNames:      []string{"example.com", "www.example.com"},
			IsCA:          false,
			ExtKeyUsage:   []string{"ServerAuth"},
		},
		Chain: []cert.ChainEntry{
			{
				Index:   0,
				Subject: "CN=example.com",
				Issuer:  "CN=Example CA",
			},
			{
				Index:   1,
				Subject: "CN=Example CA",
				Issuer:  "CN=Example Root CA",
			},
		},
		Expiry: cert.ExpiryInfo{
			NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
			DaysLeft: 365,
		},
	}
}

func TestWriteJSON(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := Write(info, config.FormatJSON, &buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Check key fields exist
	if _, ok := result["connection"]; !ok {
		t.Error("JSON output missing 'connection' field")
	}
	if _, ok := result["leaf"]; !ok {
		t.Error("JSON output missing 'leaf' field")
	}
	if _, ok := result["expiry"]; !ok {
		t.Error("JSON output missing 'expiry' field")
	}
	if _, ok := result["chain"]; !ok {
		t.Error("JSON output missing 'chain' field")
	}
}

func TestWriteYAML(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := Write(info, config.FormatYAML, &buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Verify it's valid YAML
	var result map[string]interface{}
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid YAML output: %v", err)
	}

	// Check key fields exist
	if _, ok := result["connection"]; !ok {
		t.Error("YAML output missing 'connection' field")
	}
	if _, ok := result["leaf"]; !ok {
		t.Error("YAML output missing 'leaf' field")
	}
	if _, ok := result["expiry"]; !ok {
		t.Error("YAML output missing 'expiry' field")
	}
}

func TestWriteTOML(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := Write(info, config.FormatTOML, &buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Verify it's valid TOML
	var result cert.Info
	if err := toml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Invalid TOML output: %v", err)
	}

	// Check key fields
	if result.Connection.Target == "" {
		t.Error("TOML output missing connection target")
	}
	if result.Leaf.Subject == "" {
		t.Error("TOML output missing leaf subject")
	}
}

func TestWriteText(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := Write(info, config.FormatText, &buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := buf.String()

	// Check that key information is present
	expectedStrings := []string{
		"Connected to: example.com:443",
		"TLS version:",
		"Cipher suite:",
		"SNI used:",
		"Verified:",
		"Leaf certificate",
		"Subject:",
		"Issuer:",
		"Serial:",
		"Valid from:",
		"Valid until:",
		"Expiry:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Text output missing expected string: %q", expected)
		}
	}
}

func TestWriteTextWithStartTLS(t *testing.T) {
	info := createTestCertInfo()
	info.Connection.Protocol = "smtp"
	var buf bytes.Buffer

	err := Write(info, config.FormatText, &buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SMTP STARTTLS") {
		t.Error("Text output should mention SMTP STARTTLS protocol")
	}
}

func TestWriteTextWithVerifyError(t *testing.T) {
	info := createTestCertInfo()
	info.Connection.Verified = false
	info.Connection.VerifyError = "certificate has expired"
	var buf bytes.Buffer

	err := Write(info, config.FormatText, &buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Verify error:") {
		t.Error("Text output should include verify error")
	}
	if !strings.Contains(output, "certificate has expired") {
		t.Error("Text output should include specific verify error message")
	}
}

func TestWriteTextWithEmptyChain(t *testing.T) {
	info := createTestCertInfo()
	info.Chain = nil
	var buf bytes.Buffer

	err := Write(info, config.FormatText, &buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "Peer chain") {
		t.Error("Text output should not include chain section when chain is empty")
	}
}

func TestWriteTextWithSANs(t *testing.T) {
	info := createTestCertInfo()
	info.Leaf.IPAddresses = []string{"192.0.2.1"}
	info.Leaf.EmailAddresses = []string{"admin@example.com"}
	info.Leaf.URIs = []string{"https://example.com"}
	var buf bytes.Buffer

	err := Write(info, config.FormatText, &buf)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SAN DNS:") {
		t.Error("Text output should include DNS SANs")
	}
	if !strings.Contains(output, "SAN IP:") {
		t.Error("Text output should include IP SANs")
	}
	if !strings.Contains(output, "SAN Email:") {
		t.Error("Text output should include Email SANs")
	}
	if !strings.Contains(output, "SAN URI:") {
		t.Error("Text output should include URI SANs")
	}
}

func TestWriteUnsupportedFormat(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := Write(info, config.OutputFormat("invalid"), &buf)
	if err == nil {
		t.Error("Write() should return error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("Error message should mention unsupported format, got: %v", err)
	}
}

func TestWriteJSONStructure(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := writeJSON(info, &buf)
	if err != nil {
		t.Fatalf("writeJSON() error = %v", err)
	}

	var result cert.Info
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify structure
	if result.Connection.Target != info.Connection.Target {
		t.Errorf("Target = %v, want %v", result.Connection.Target, info.Connection.Target)
	}
	if result.Leaf.Subject != info.Leaf.Subject {
		t.Errorf("Subject = %v, want %v", result.Leaf.Subject, info.Leaf.Subject)
	}
	if len(result.Chain) != len(info.Chain) {
		t.Errorf("Chain length = %v, want %v", len(result.Chain), len(info.Chain))
	}
}

func TestWriteYAMLStructure(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := writeYAML(info, &buf)
	if err != nil {
		t.Fatalf("writeYAML() error = %v", err)
	}

	var result cert.Info
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Verify structure
	if result.Connection.Target != info.Connection.Target {
		t.Errorf("Target = %v, want %v", result.Connection.Target, info.Connection.Target)
	}
	if result.Leaf.Subject != info.Leaf.Subject {
		t.Errorf("Subject = %v, want %v", result.Leaf.Subject, info.Leaf.Subject)
	}
}

func TestWriteTOMLStructure(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := writeTOML(info, &buf)
	if err != nil {
		t.Fatalf("writeTOML() error = %v", err)
	}

	var result cert.Info
	if err := toml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal TOML: %v", err)
	}

	// Verify structure
	if result.Connection.Target != info.Connection.Target {
		t.Errorf("Target = %v, want %v", result.Connection.Target, info.Connection.Target)
	}
	if result.Leaf.Subject != info.Leaf.Subject {
		t.Errorf("Subject = %v, want %v", result.Leaf.Subject, info.Leaf.Subject)
	}
}

func TestWriteTextWithChain(t *testing.T) {
	info := createTestCertInfo()
	var buf bytes.Buffer

	err := writeText(info, &buf)
	if err != nil {
		t.Fatalf("writeText() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Peer chain (as presented):") {
		t.Error("Text output should include peer chain section")
	}
	if !strings.Contains(output, "[0] Subject:") {
		t.Error("Text output should include chain entry 0")
	}
	if !strings.Contains(output, "[1] Subject:") {
		t.Error("Text output should include chain entry 1")
	}
}

func TestWriteTextMinimal(t *testing.T) {
	// Test with minimal certificate info (no optional fields)
	info := &cert.Info{
		Connection: cert.ConnectionInfo{
			Target:      "test.com:443",
			TLSVersion:  "TLS1.2",
			CipherSuite: "TLS_RSA_WITH_AES_128_GCM_SHA256",
			SNI:         "test.com",
			Verified:    true,
		},
		Leaf: cert.Certificate{
			Subject:       "CN=test.com",
			Issuer:        "CN=Test CA",
			SerialNumber:  "1",
			NotBefore:     time.Now().Format(time.RFC3339),
			NotAfter:      time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
			SignatureAlgo: "SHA256-RSA",
			PublicKey:     "RSA (2048 bits)",
			IsCA:          false,
		},
		Expiry: cert.ExpiryInfo{
			NotAfter: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
			DaysLeft: 365,
		},
	}
	var buf bytes.Buffer

	err := writeText(info, &buf)
	if err != nil {
		t.Fatalf("writeText() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Connected to: test.com:443") {
		t.Error("Text output should include connection target")
	}
	if !strings.Contains(output, "Leaf certificate") {
		t.Error("Text output should include leaf certificate section")
	}
	if strings.Contains(output, "SAN DNS:") {
		t.Error("Text output should not include SAN DNS when not present")
	}
	if strings.Contains(output, "ExtKeyUsage:") {
		t.Error("Text output should not include ExtKeyUsage when not present")
	}
}

func TestPrintCertTextWithAllFields(t *testing.T) {
	cert := cert.Certificate{
		Subject:        "CN=test.example.com",
		Issuer:         "CN=Test CA",
		SerialNumber:   "abc123",
		NotBefore:      "2024-01-01T00:00:00Z",
		NotAfter:       "2025-01-01T00:00:00Z",
		SignatureAlgo:  "SHA256-RSA",
		PublicKey:      "RSA (2048 bits)",
		DNSNames:       []string{"test.example.com", "www.test.example.com"},
		IPAddresses:    []string{"192.0.2.1", "192.0.2.2"},
		EmailAddresses: []string{"admin@test.example.com", "support@test.example.com"},
		URIs:           []string{"https://test.example.com", "https://www.test.example.com"},
		IsCA:           false,
		ExtKeyUsage:    []string{"ServerAuth", "ClientAuth"},
	}
	var buf bytes.Buffer

	err := printCertText("Test Certificate", cert, &buf)
	if err != nil {
		t.Fatalf("printCertText() error = %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"Test Certificate",
		"Subject:",
		"Issuer:",
		"Serial:",
		"Valid from:",
		"Valid until:",
		"Signature algo:",
		"Public key:",
		"SAN DNS:",
		"SAN IP:",
		"SAN Email:",
		"SAN URI:",
		"Is CA:",
		"ExtKeyUsage:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("printCertText output missing expected string: %q", expected)
		}
	}
}
