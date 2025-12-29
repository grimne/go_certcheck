package main

import (
	"fmt"
	"net"
	"os"

	"github.com/grimne/certcheck/internal/config"
	"github.com/grimne/certcheck/internal/connection"
	"github.com/grimne/certcheck/internal/output"
)

func main() {
	cfg := config.Parse()

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	target := net.JoinHostPort(cfg.Host, cfg.Port)

	// Fetch certificate info
	certInfo, err := connection.FetchCertInfo(target, cfg)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate: %w", err)
	}

	// Output results
	return output.Write(certInfo, cfg.OutputFormat, os.Stdout)
}
