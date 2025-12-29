package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// OutputFormat represents the desired output format
type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
	FormatYAML OutputFormat = "yaml"
	FormatTOML OutputFormat = "toml"
)

// StartTLSProtocol represents supported STARTTLS protocols
type StartTLSProtocol string

const (
	ProtocolNone StartTLSProtocol = ""
	ProtocolSMTP StartTLSProtocol = "smtp"
	ProtocolIMAP StartTLSProtocol = "imap"
	ProtocolPOP3 StartTLSProtocol = "pop3"
	ProtocolFTP  StartTLSProtocol = "ftp"
	ProtocolXMPP StartTLSProtocol = "xmpp"
)

// Default ports for protocols
var defaultPorts = map[StartTLSProtocol]string{
	ProtocolNone: "443",
	ProtocolSMTP: "25",    // or 587 for submission
	ProtocolIMAP: "143",
	ProtocolPOP3: "110",
	ProtocolFTP:  "21",
	ProtocolXMPP: "5222",
}

// CertInfo holds all certificate information for structured output
type CertInfo struct {
	Connection ConnectionInfo `json:"connection" yaml:"connection" toml:"connection"`
	Leaf       Certificate    `json:"leaf" yaml:"leaf" toml:"leaf"`
	Chain      []ChainEntry   `json:"chain,omitempty" yaml:"chain,omitempty" toml:"chain,omitempty"`
	Expiry     ExpiryInfo     `json:"expiry" yaml:"expiry" toml:"expiry"`
}

type ConnectionInfo struct {
	Target      string `json:"target" yaml:"target" toml:"target"`
	TLSVersion  string `json:"tls_version" yaml:"tls_version" toml:"tls_version"`
	CipherSuite string `json:"cipher_suite" yaml:"cipher_suite" toml:"cipher_suite"`
	SNI         string `json:"sni" yaml:"sni" toml:"sni"`
	Verified    bool   `json:"verified" yaml:"verified" toml:"verified"`
	VerifyError string `json:"verify_error,omitempty" yaml:"verify_error,omitempty" toml:"verify_error,omitempty"`
	Protocol    string `json:"protocol,omitempty" yaml:"protocol,omitempty" toml:"protocol,omitempty"`
}

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

type ChainEntry struct {
	Index   int    `json:"index" yaml:"index" toml:"index"`
	Subject string `json:"subject" yaml:"subject" toml:"subject"`
	Issuer  string `json:"issuer" yaml:"issuer" toml:"issuer"`
}

type ExpiryInfo struct {
	NotAfter string `json:"not_after" yaml:"not_after" toml:"not_after"`
	DaysLeft int    `json:"days_left" yaml:"days_left" toml:"days_left"`
}

type config struct {
	serverName string
	timeout    time.Duration
	startTLS   StartTLSProtocol
	printChain bool
	output     OutputFormat
}

func main() {
	cfg := parseFlags()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(2)
	}

	target := flag.Arg(0)

	// Get default port based on protocol
	defaultPort := defaultPorts[cfg.startTLS]
	if defaultPort == "" {
		defaultPort = "443"
	}

	host, port, err := splitHostPortDefault(target, defaultPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	target = net.JoinHostPort(host, port)

	if cfg.serverName == "" {
		cfg.serverName = host
	}

	certInfo, err := fetchCertInfo(target, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := outputCertInfo(certInfo, cfg.output); err != nil {
		fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	var outputStr, startTLSStr string

	flag.StringVar(&cfg.serverName, "sni", "", "SNI / ServerName override (default: host from target)")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "dial timeout (e.g. 10s)")
	flag.StringVar(&startTLSStr, "starttls", "", "starttls protocol: smtp|imap|pop3|ftp|xmpp")
	flag.BoolVar(&cfg.printChain, "chain", true, "include certificate chain in output")
	flag.StringVar(&outputStr, "o", "text", "output format: text|json|yaml|toml")
	flag.Parse()

	cfg.output = OutputFormat(strings.ToLower(outputStr))
	if !isValidFormat(cfg.output) {
		fmt.Fprintf(os.Stderr, "Invalid output format: %s (valid: text, json, yaml, toml)\n", outputStr)
		os.Exit(2)
	}

	cfg.startTLS = StartTLSProtocol(strings.ToLower(startTLSStr))
	if startTLSStr != "" && !isValidStartTLS(cfg.startTLS) {
		fmt.Fprintf(os.Stderr, "Invalid starttls protocol: %s (valid: smtp, imap, pop3, ftp, xmpp)\n", startTLSStr)
		os.Exit(2)
	}

	return cfg
}

func isValidFormat(format OutputFormat) bool {
	return format == FormatText || format == FormatJSON || format == FormatYAML || format == FormatTOML
}

func isValidStartTLS(proto StartTLSProtocol) bool {
	return proto == ProtocolSMTP || proto == ProtocolIMAP || proto == ProtocolPOP3 ||
	       proto == ProtocolFTP || proto == ProtocolXMPP
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [flags] target\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  certcheck example.com")
	fmt.Fprintln(os.Stderr, "  certcheck example.com:443")
	fmt.Fprintln(os.Stderr, "  certcheck -sni www.example.com 1.2.3.4")
	fmt.Fprintln(os.Stderr, "  certcheck -o json example.com")
	fmt.Fprintln(os.Stderr, "  certcheck -starttls smtp mail.example.com:25")
	fmt.Fprintln(os.Stderr, "  certcheck -starttls imap mail.example.com:143")
	fmt.Fprintln(os.Stderr, "  certcheck -starttls pop3 mail.example.com")
	fmt.Fprintln(os.Stderr)
	flag.PrintDefaults()
}

func fetchCertInfo(target string, cfg config) (*CertInfo, error) {
	var conn *tls.Conn
	var err error

	if cfg.startTLS != ProtocolNone {
		conn, err = dialStartTLS(target, cfg)
	} else {
		conn, err = dialDirectTLS(target, cfg)
	}

	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates presented")
	}

	verified, verifyErr := verifyPeerCertificates(state.PeerCertificates, cfg.serverName)

	info := &CertInfo{
		Connection: ConnectionInfo{
			Target:      target,
			TLSVersion:  tlsVersion(state.Version),
			CipherSuite: tls.CipherSuiteName(state.CipherSuite),
			SNI:         cfg.serverName,
			Verified:    verified,
		},
		Leaf:   buildCertificate(state.PeerCertificates[0]),
		Expiry: buildExpiryInfo(state.PeerCertificates[0]),
	}

	if cfg.startTLS != ProtocolNone {
		info.Connection.Protocol = string(cfg.startTLS)
	}

	if !verified && verifyErr != nil {
		info.Connection.VerifyError = verifyErr.Error()
	}

	if cfg.printChain {
		info.Chain = make([]ChainEntry, len(state.PeerCertificates))
		for i, cert := range state.PeerCertificates {
			info.Chain[i] = ChainEntry{
				Index:   i,
				Subject: formatDN(cert.Subject),
				Issuer:  formatDN(cert.Issuer),
			}
		}
	}

	return info, nil
}

func dialDirectTLS(target string, cfg config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.timeout}
	tlsConfig := &tls.Config{
		ServerName:         cfg.serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connect failed: %w", err)
	}
	return conn, nil
}

func dialStartTLS(target string, cfg config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.timeout}

	// Connect to plaintext port first
	netConn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}

	// Perform protocol-specific STARTTLS handshake
	if err := performStartTLS(netConn, cfg.startTLS, cfg.serverName); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("STARTTLS handshake failed: %w", err)
	}

	// Upgrade to TLS
	tlsConfig := &tls.Config{
		ServerName:         cfg.serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(netConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

func performStartTLS(conn net.Conn, proto StartTLSProtocol, serverName string) error {
	reader := bufio.NewReader(conn)

	switch proto {
	case ProtocolSMTP:
		return startTLSSMTP(conn, reader, serverName)
	case ProtocolIMAP:
		return startTLSIMAP(conn, reader)
	case ProtocolPOP3:
		return startTLSPOP3(conn, reader)
	case ProtocolFTP:
		return startTLSFTP(conn, reader)
	case ProtocolXMPP:
		return startTLSXMPP(conn, reader, serverName)
	default:
		return fmt.Errorf("unsupported STARTTLS protocol: %s", proto)
	}
}

func startTLSSMTP(conn net.Conn, reader *bufio.Reader, serverName string) error {
	// Read greeting
	if _, err := readSMTPResponse(reader, "220"); err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}

	// Send EHLO
	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", serverName); err != nil {
		return err
	}
	if _, err := readSMTPResponse(reader, "250"); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}

	// Send STARTTLS
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	if _, err := readSMTPResponse(reader, "220"); err != nil {
		return fmt.Errorf("STARTTLS: %w", err)
	}

	return nil
}

func startTLSIMAP(conn net.Conn, reader *bufio.Reader) error {
	// Read greeting
	if _, err := reader.ReadString('\n'); err != nil {
		return fmt.Errorf("IMAP greeting: %w", err)
	}

	// Send STARTTLS
	if _, err := fmt.Fprintf(conn, "a001 STARTTLS\r\n"); err != nil {
		return err
	}

	// Read response
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("STARTTLS response: %w", err)
	}
	if !strings.Contains(response, "OK") {
		return fmt.Errorf("STARTTLS not accepted: %s", strings.TrimSpace(response))
	}

	return nil
}

func startTLSPOP3(conn net.Conn, reader *bufio.Reader) error {
	// Read greeting
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("POP3 greeting: %w", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		return fmt.Errorf("bad POP3 greeting: %s", strings.TrimSpace(response))
	}

	// Send STLS
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return err
	}

	// Read response
	response, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("STLS response: %w", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		return fmt.Errorf("STLS not accepted: %s", strings.TrimSpace(response))
	}

	return nil
}

func startTLSFTP(conn net.Conn, reader *bufio.Reader) error {
	// Read greeting
	if _, err := readFTPResponse(reader, "220"); err != nil {
		return fmt.Errorf("FTP greeting: %w", err)
	}

	// Send AUTH TLS
	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return err
	}

	// Read response
	if _, err := readFTPResponse(reader, "234"); err != nil {
		return fmt.Errorf("AUTH TLS: %w", err)
	}

	return nil
}

func startTLSXMPP(conn net.Conn, reader *bufio.Reader, serverName string) error {
	// Send initial stream header
	streamHeader := fmt.Sprintf("<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", serverName)
	if _, err := fmt.Fprintf(conn, "%s", streamHeader); err != nil {
		return err
	}

	// Read server's stream header (simple version - just look for stream:features)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("reading XMPP stream: %w", err)
	}
	response := string(buf[:n])

	if !strings.Contains(response, "<stream:features") {
		return fmt.Errorf("no stream features in response")
	}

	// Send STARTTLS
	if _, err := fmt.Fprintf(conn, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"); err != nil {
		return err
	}

	// Read proceed
	n, err = conn.Read(buf)
	if err != nil {
		return fmt.Errorf("reading STARTTLS response: %w", err)
	}
	response = string(buf[:n])

	if !strings.Contains(response, "<proceed") {
		return fmt.Errorf("STARTTLS not accepted")
	}

	return nil
}

func readSMTPResponse(reader *bufio.Reader, expectedCode string) (string, error) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)

		if len(line) < 4 {
			continue
		}

		code := line[:3]
		if code != expectedCode {
			return "", fmt.Errorf("unexpected response code %s (expected %s): %s", code, expectedCode, line)
		}

		// Check if this is the last line (space after code, not dash)
		if len(line) > 3 && line[3] == ' ' {
			return line, nil
		}
	}
}

func readFTPResponse(reader *bufio.Reader, expectedCode string) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)

	if len(line) < 4 {
		return "", fmt.Errorf("response too short: %s", line)
	}

	code := line[:3]
	if code != expectedCode {
		return "", fmt.Errorf("unexpected response code %s (expected %s): %s", code, expectedCode, line)
	}

	return line, nil
}

func buildCertificate(cert *x509.Certificate) Certificate {
	c := Certificate{
		Subject:        formatDN(cert.Subject),
		Issuer:         formatDN(cert.Issuer),
		SerialNumber:   cert.SerialNumber.Text(16),
		NotBefore:      cert.NotBefore.Format(time.RFC3339),
		NotAfter:       cert.NotAfter.Format(time.RFC3339),
		SignatureAlgo:  cert.SignatureAlgorithm.String(),
		PublicKey:      publicKeySummary(cert),
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
			c.ExtKeyUsage[i] = extKeyUsageToString(usage)
		}
	}

	return c
}

func buildExpiryInfo(cert *x509.Certificate) ExpiryInfo {
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return ExpiryInfo{
		NotAfter: cert.NotAfter.Format(time.RFC3339),
		DaysLeft: daysLeft,
	}
}

func outputCertInfo(info *CertInfo, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return outputJSON(info)
	case FormatYAML:
		return outputYAML(info)
	case FormatTOML:
		return outputTOML(info)
	case FormatText:
		return outputText(info)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func outputJSON(info *CertInfo) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

func outputYAML(info *CertInfo) error {
	enc := yaml.NewEncoder(os.Stdout)
	defer enc.Close()
	return enc.Encode(info)
}

func outputTOML(info *CertInfo) error {
	return toml.NewEncoder(os.Stdout).Encode(info)
}

func outputText(info *CertInfo) error {
	fmt.Printf("Connected to: %s", info.Connection.Target)
	if info.Connection.Protocol != "" {
		fmt.Printf(" (via %s STARTTLS)", strings.ToUpper(info.Connection.Protocol))
	}
	fmt.Println()

	fmt.Printf("TLS version:  %s\n", info.Connection.TLSVersion)
	fmt.Printf("Cipher suite: %s\n", info.Connection.CipherSuite)
	fmt.Printf("SNI used:     %s\n", info.Connection.SNI)
	fmt.Printf("Verified:     %s\n", colorBool(info.Connection.Verified))

	if !info.Connection.Verified && info.Connection.VerifyError != "" {
		fmt.Printf("Verify error: %s\n", info.Connection.VerifyError)
	}
	fmt.Println()

	printCertText("Leaf certificate", info.Leaf)

	if len(info.Chain) > 0 {
		fmt.Println("\nPeer chain (as presented):")
		for _, entry := range info.Chain {
			fmt.Printf("  [%d] Subject: %s\n", entry.Index, entry.Subject)
			fmt.Printf("      Issuer:  %s\n", entry.Issuer)
		}
	}

	fmt.Printf("\nExpiry: %s (%d days left)\n", info.Expiry.NotAfter, info.Expiry.DaysLeft)
	return nil
}

func printCertText(title string, c Certificate) {
	fmt.Println(title)
	fmt.Println(strings.Repeat("-", len(title)))
	fmt.Printf("Subject:        %s\n", c.Subject)
	fmt.Printf("Issuer:         %s\n", c.Issuer)
	fmt.Printf("Serial:         %s\n", c.SerialNumber)
	fmt.Printf("Valid from:     %s\n", c.NotBefore)
	fmt.Printf("Valid until:    %s\n", c.NotAfter)
	fmt.Printf("Signature algo: %s\n", c.SignatureAlgo)
	fmt.Printf("Public key:     %s\n", c.PublicKey)

	if len(c.DNSNames) > 0 {
		fmt.Printf("SAN DNS:        %s\n", strings.Join(c.DNSNames, ", "))
	}
	if len(c.IPAddresses) > 0 {
		fmt.Printf("SAN IP:         %s\n", strings.Join(c.IPAddresses, ", "))
	}
	if len(c.EmailAddresses) > 0 {
		fmt.Printf("SAN Email:      %s\n", strings.Join(c.EmailAddresses, ", "))
	}
	if len(c.URIs) > 0 {
		fmt.Printf("SAN URI:        %s\n", strings.Join(c.URIs, ", "))
	}

	fmt.Printf("Is CA:          %v\n", c.IsCA)
	if len(c.ExtKeyUsage) > 0 {
		fmt.Printf("ExtKeyUsage:    %s\n", strings.Join(c.ExtKeyUsage, ", "))
	}
}

func verifyPeerCertificates(peer []*x509.Certificate, serverName string) (bool, error) {
	leaf := peer[0]

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}

	intermediates := x509.NewCertPool()
	for _, ic := range peer[1:] {
		intermediates.AddCert(ic)
	}

	opts := x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	if _, err := leaf.Verify(opts); err != nil {
		return false, err
	}
	return true, nil
}

func colorBool(ok bool) string {
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

func splitHostPortDefault(input, defaultPort string) (host, port string, err error) {
	if h, p, e := net.SplitHostPort(input); e == nil {
		return h, p, nil
	}

	// IPv6 without port
	if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		h := input[1 : len(input)-1]
		return h, defaultPort, nil
	}

	// IPv6 without brackets
	if strings.Count(input, ":") >= 2 && !strings.HasPrefix(input, "[") {
		return input, defaultPort, nil
	}

	// Invalid input
	if strings.Contains(input, " ") || input == "" {
		return "", "", fmt.Errorf("invalid target: %q", input)
	}

	return input, defaultPort, nil
}

func formatDN(n pkix.Name) string {
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

func tlsVersion(v uint16) string {
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

func publicKeySummary(c *x509.Certificate) string {
	switch pk := c.PublicKey.(type) {
	case interface{ Size() int }:
		return fmt.Sprintf("%T (%d bits)", c.PublicKey, pk.Size()*8)
	default:
		return fmt.Sprintf("%T", c.PublicKey)
	}
}

func extKeyUsageToString(u x509.ExtKeyUsage) string {
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
