package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		serverName string
		timeout    time.Duration
		startTLS   string // reserved for future expansion (smtp/imap starttls)
		printChain bool
	)

	flag.StringVar(&serverName, "sni", "", "SNI / ServerName override (default: host from target)")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "dial timeout (e.g. 5s)")
	flag.StringVar(&startTLS, "starttls", "", "starttls mode (not implemented in this minimal sample): smtp|imap|pop3")
	flag.BoolVar(&printChain, "chain", true, "print peer chain summary")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] target\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  certcheck example.com")
		fmt.Fprintln(os.Stderr, "  certcheck example.com:443")
		fmt.Fprintln(os.Stderr, "  certcheck -sni www.example.com 1.2.3.4")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
		os.Exit(2)
	}
	target := flag.Arg(0)

	if startTLS != "" {
		fmt.Fprintln(os.Stderr, "Note: -starttls is not implemented in this minimal sample. Use direct TLS ports (443/465/993/etc.).")
	}

	// If no port provided, assume 443.
	host, port, err := splitHostPortDefault(target, "443")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	target = net.JoinHostPort(host, port)

	if serverName == "" {
		serverName = host
	}

	dialer := &net.Dialer{Timeout: timeout}

	// Always skip verification during handshake so we can *always* fetch/inspect certs.
	// We'll do our own verification afterward and print the result clearly.
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", target, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLS connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	fmt.Printf("Connected to: %s\n", target)
	fmt.Printf("TLS version:  %s\n", tlsVersion(state.Version))
	fmt.Printf("Cipher suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("SNI used:     %s\n", serverName)

	if len(state.PeerCertificates) == 0 {
		fmt.Println("\nNo peer certificates presented.")
		return
	}

	verified, verifyErr := verifyPeerCertificates(state.PeerCertificates, serverName)
	fmt.Printf("Verified:     %s\n", colorBool(verified))
	if !verified {
		// Keep it brief but useful
		fmt.Printf("Verify error:  %v\n", verifyErr)
	}
	fmt.Println()

	leaf := state.PeerCertificates[0]
	printCert("Leaf certificate", leaf)

	if printChain {
		fmt.Println("\nPeer chain (as presented):")
		for i, c := range state.PeerCertificates {
			fmt.Printf("  [%d] Subject: %s\n", i, dn(c.Subject))
			fmt.Printf("      Issuer:  %s\n", dn(c.Issuer))
		}
	}

	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
	fmt.Printf("\nExpiry: %s (%d days left)\n", leaf.NotAfter.Format(time.RFC3339), daysLeft)
}

// verifyPeerCertificates verifies the leaf cert using system roots + provided intermediates,
// and checks hostname (like browsers do).
func verifyPeerCertificates(peer []*x509.Certificate, serverName string) (bool, error) {
	leaf := peer[0]

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		// On some systems this can fail; fall back to an empty pool (will likely fail verify).
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

	_, verr := leaf.Verify(opts)
	if verr != nil {
		return false, verr
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

func splitHostPortDefault(input string, defaultPort string) (host, port string, err error) {
	if h, p, e := net.SplitHostPort(input); e == nil {
		return h, p, nil
	}
	if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		h := strings.TrimPrefix(strings.TrimSuffix(input, "]"), "[")
		return h, defaultPort, nil
	}
	if strings.Count(input, ":") >= 2 && !strings.HasPrefix(input, "[") {
		return input, defaultPort, nil
	}
	if strings.Contains(input, " ") || input == "" {
		return "", "", fmt.Errorf("Invalid target: %q", input)
	}
	return input, defaultPort, nil
}

func printCert(title string, c *x509.Certificate) {
	fmt.Println(title)
	fmt.Println(strings.Repeat("-", len(title)))
	fmt.Printf("Subject:        %s\n", dn(c.Subject))
	fmt.Printf("Issuer:         %s\n", dn(c.Issuer))
	fmt.Printf("Serial:         %s\n", c.SerialNumber.Text(16))
	fmt.Printf("Valid from:     %s\n", c.NotBefore.Format(time.RFC3339))
	fmt.Printf("Valid until:    %s\n", c.NotAfter.Format(time.RFC3339))
	fmt.Printf("Signature algo: %s\n", c.SignatureAlgorithm.String())
	fmt.Printf("Public key:     %s\n", publicKeySummary(c))

	if len(c.DNSNames) > 0 {
		fmt.Printf("SAN DNS:        %s\n", strings.Join(c.DNSNames, ", "))
	}
	if len(c.IPAddresses) > 0 {
		ips := make([]string, 0, len(c.IPAddresses))
		for _, ip := range c.IPAddresses {
			ips = append(ips, ip.String())
		}
		fmt.Printf("SAN IP:         %s\n", strings.Join(ips, ", "))
	}
	if len(c.EmailAddresses) > 0 {
		fmt.Printf("SAN Email:      %s\n", strings.Join(c.EmailAddresses, ", "))
	}
	if len(c.URIs) > 0 {
		uris := make([]string, 0, len(c.URIs))
		for _, u := range c.URIs {
			uris = append(uris, u.String())
		}
		fmt.Printf("SAN URI:        %s\n", strings.Join(uris, ", "))
	}

	fmt.Printf("Is CA:          %v\n", c.IsCA)
	if len(c.ExtKeyUsage) > 0 {
		fmt.Printf("ExtKeyUsage:    %s\n", extKeyUsageSummary(c.ExtKeyUsage))
	}
}

func dn(n pkix.Name) string {
	parts := []string{}
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

func extKeyUsageSummary(usages []x509.ExtKeyUsage) string {
	out := make([]string, 0, len(usages))
	for _, u := range usages {
		out = append(out, extKeyUsageToString(u))
	}
	return strings.Join(out, ", ")
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
