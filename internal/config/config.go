package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
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

// Config holds application configuration
type Config struct {
	Host         string
	Port         string
	ServerName   string
	Timeout      time.Duration
	StartTLS     StartTLSProtocol
	PrintChain   bool
	OutputFormat OutputFormat
}

var defaultPorts = map[StartTLSProtocol]string{
	ProtocolNone: "443",
	ProtocolSMTP: "25",
	ProtocolIMAP: "143",
	ProtocolPOP3: "110",
	ProtocolFTP:  "21",
	ProtocolXMPP: "5222",
}

// Parse parses command-line flags and returns configuration
func Parse() *Config {
	var (
		serverName string
		timeout    time.Duration
		startTLS   string
		printChain bool
		output     string
	)

	flag.StringVar(&serverName, "sni", "", "SNI / ServerName override (default: host from target)")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "dial timeout (e.g. 10s)")
	flag.StringVar(&startTLS, "starttls", "", "starttls protocol: smtp|imap|pop3|ftp|xmpp")
	flag.BoolVar(&printChain, "chain", true, "include certificate chain in output")
	flag.StringVar(&output, "o", "text", "output format: text|json|yaml|toml")
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(2)
	}

	target := flag.Arg(0)
	proto := StartTLSProtocol(strings.ToLower(startTLS))

	if startTLS != "" && !isValidStartTLS(proto) {
		fmt.Fprintf(os.Stderr, "Invalid starttls protocol: %s (valid: smtp, imap, pop3, ftp, xmpp)\n", startTLS)
		os.Exit(2)
	}

	outputFormat := OutputFormat(strings.ToLower(output))
	if !isValidFormat(outputFormat) {
		fmt.Fprintf(os.Stderr, "Invalid output format: %s (valid: text, json, yaml, toml)\n", output)
		os.Exit(2)
	}

	defaultPort := defaultPorts[proto]
	if defaultPort == "" {
		defaultPort = "443"
	}

	host, port, err := splitHostPortDefault(target, defaultPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if serverName == "" {
		serverName = host
	}

	return &Config{
		Host:         host,
		Port:         port,
		ServerName:   serverName,
		Timeout:      timeout,
		StartTLS:     proto,
		PrintChain:   printChain,
		OutputFormat: outputFormat,
	}
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
	fmt.Fprintln(os.Stderr)
	flag.PrintDefaults()
}

func isValidFormat(format OutputFormat) bool {
	return format == FormatText || format == FormatJSON ||
	       format == FormatYAML || format == FormatTOML
}

func isValidStartTLS(proto StartTLSProtocol) bool {
	return proto == ProtocolSMTP || proto == ProtocolIMAP ||
	       proto == ProtocolPOP3 || proto == ProtocolFTP ||
	       proto == ProtocolXMPP
}

func splitHostPortDefault(input, defaultPort string) (host, port string, err error) {
	if h, p, e := net.SplitHostPort(input); e == nil {
		return h, p, nil
	}

	if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		h := input[1 : len(input)-1]
		return h, defaultPort, nil
	}

	if strings.Count(input, ":") >= 2 && !strings.HasPrefix(input, "[") {
		return input, defaultPort, nil
	}

	if strings.Contains(input, " ") || input == "" {
		return "", "", fmt.Errorf("invalid target: %q", input)
	}

	return input, defaultPort, nil
}
