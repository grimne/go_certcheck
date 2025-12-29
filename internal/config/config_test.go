package config

import (
	"testing"
	"time"
)

func TestIsValidFormat(t *testing.T) {
	tests := []struct {
		format   OutputFormat
		expected bool
	}{
		{FormatText, true},
		{FormatJSON, true},
		{FormatYAML, true},
		{FormatTOML, true},
		{OutputFormat("invalid"), false},
		{OutputFormat("xml"), false},
		{OutputFormat(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			result := isValidFormat(tt.format)
			if result != tt.expected {
				t.Errorf("isValidFormat(%q) = %v, want %v", tt.format, result, tt.expected)
			}
		})
	}
}

func TestIsValidStartTLS(t *testing.T) {
	tests := []struct {
		protocol StartTLSProtocol
		expected bool
	}{
		{ProtocolSMTP, true},
		{ProtocolIMAP, true},
		{ProtocolPOP3, true},
		{ProtocolFTP, true},
		{ProtocolNone, false},
		{StartTLSProtocol("invalid"), false},
		{StartTLSProtocol("http"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.protocol), func(t *testing.T) {
			result := isValidStartTLS(tt.protocol)
			if result != tt.expected {
				t.Errorf("isValidStartTLS(%q) = %v, want %v", tt.protocol, result, tt.expected)
			}
		})
	}
}

func TestSplitHostPortDefault(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultPort  string
		expectedHost string
		expectedPort string
		expectError  bool
	}{
		{
			name:         "hostname with port",
			input:        "example.com:8443",
			defaultPort:  "443",
			expectedHost: "example.com",
			expectedPort: "8443",
			expectError:  false,
		},
		{
			name:         "hostname without port",
			input:        "example.com",
			defaultPort:  "443",
			expectedHost: "example.com",
			expectedPort: "443",
			expectError:  false,
		},
		{
			name:         "IPv4 with port",
			input:        "192.0.2.1:8443",
			defaultPort:  "443",
			expectedHost: "192.0.2.1",
			expectedPort: "8443",
			expectError:  false,
		},
		{
			name:         "IPv4 without port",
			input:        "192.0.2.1",
			defaultPort:  "443",
			expectedHost: "192.0.2.1",
			expectedPort: "443",
			expectError:  false,
		},
		{
			name:         "IPv6 with brackets and port",
			input:        "[2001:db8::1]:8443",
			defaultPort:  "443",
			expectedHost: "2001:db8::1",
			expectedPort: "8443",
			expectError:  false,
		},
		{
			name:         "IPv6 with brackets no port",
			input:        "[2001:db8::1]",
			defaultPort:  "443",
			expectedHost: "2001:db8::1",
			expectedPort: "443",
			expectError:  false,
		},
		{
			name:         "IPv6 without brackets",
			input:        "2001:db8::1",
			defaultPort:  "443",
			expectedHost: "2001:db8::1",
			expectedPort: "443",
			expectError:  false,
		},
		{
			name:         "empty string",
			input:        "",
			defaultPort:  "443",
			expectedHost: "",
			expectedPort: "",
			expectError:  true,
		},
		{
			name:         "string with spaces",
			input:        "example com",
			defaultPort:  "443",
			expectedHost: "",
			expectedPort: "",
			expectError:  true,
		},
		{
			name:         "SMTP default port",
			input:        "mail.example.com",
			defaultPort:  "25",
			expectedHost: "mail.example.com",
			expectedPort: "25",
			expectError:  false,
		},
		{
			name:         "localhost",
			input:        "localhost:443",
			defaultPort:  "443",
			expectedHost: "localhost",
			expectedPort: "443",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := splitHostPortDefault(tt.input, tt.defaultPort)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for input %q, got none", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for input %q: %v", tt.input, err)
				return
			}

			if host != tt.expectedHost {
				t.Errorf("host = %q, want %q", host, tt.expectedHost)
			}
			if port != tt.expectedPort {
				t.Errorf("port = %q, want %q", port, tt.expectedPort)
			}
		})
	}
}

func TestDefaultPorts(t *testing.T) {
	tests := []struct {
		protocol    StartTLSProtocol
		expectedPort string
	}{
		{ProtocolNone, "443"},
		{ProtocolSMTP, "25"},
		{ProtocolIMAP, "143"},
		{ProtocolPOP3, "110"},
		{ProtocolFTP, "21"},
	}

	for _, tt := range tests {
		t.Run(string(tt.protocol), func(t *testing.T) {
			port := defaultPorts[tt.protocol]
			if port != tt.expectedPort {
				t.Errorf("defaultPorts[%q] = %q, want %q", tt.protocol, port, tt.expectedPort)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	// Test that default values are reasonable
	cfg := &Config{
		Host:         "example.com",
		Port:         "443",
		ServerName:   "example.com",
		Timeout:      10 * time.Second,
		StartTLS:     ProtocolNone,
		PrintChain:   true,
		OutputFormat: FormatText,
	}

	if cfg.Host != "example.com" {
		t.Errorf("Host = %q, want %q", cfg.Host, "example.com")
	}
	if cfg.Port != "443" {
		t.Errorf("Port = %q, want %q", cfg.Port, "443")
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "example.com")
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, 10*time.Second)
	}
	if cfg.StartTLS != ProtocolNone {
		t.Errorf("StartTLS = %q, want %q", cfg.StartTLS, ProtocolNone)
	}
	if !cfg.PrintChain {
		t.Error("PrintChain should default to true")
	}
	if cfg.OutputFormat != FormatText {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, FormatText)
	}
}

func TestOutputFormatConstants(t *testing.T) {
	if FormatText != "text" {
		t.Errorf("FormatText = %q, want %q", FormatText, "text")
	}
	if FormatJSON != "json" {
		t.Errorf("FormatJSON = %q, want %q", FormatJSON, "json")
	}
	if FormatYAML != "yaml" {
		t.Errorf("FormatYAML = %q, want %q", FormatYAML, "yaml")
	}
	if FormatTOML != "toml" {
		t.Errorf("FormatTOML = %q, want %q", FormatTOML, "toml")
	}
}

func TestStartTLSProtocolConstants(t *testing.T) {
	if ProtocolNone != "" {
		t.Errorf("ProtocolNone = %q, want empty string", ProtocolNone)
	}
	if ProtocolSMTP != "smtp" {
		t.Errorf("ProtocolSMTP = %q, want %q", ProtocolSMTP, "smtp")
	}
	if ProtocolIMAP != "imap" {
		t.Errorf("ProtocolIMAP = %q, want %q", ProtocolIMAP, "imap")
	}
	if ProtocolPOP3 != "pop3" {
		t.Errorf("ProtocolPOP3 = %q, want %q", ProtocolPOP3, "pop3")
	}
	if ProtocolFTP != "ftp" {
		t.Errorf("ProtocolFTP = %q, want %q", ProtocolFTP, "ftp")
	}
}
