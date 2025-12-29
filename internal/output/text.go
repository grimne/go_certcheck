package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/grimne/certcheck/internal/cert"
)

func writeText(info *cert.Info, w io.Writer) error {
	fmt.Fprintf(w, "Connected to: %s", info.Connection.Target)
	if info.Connection.Protocol != "" {
		fmt.Fprintf(w, " (via %s STARTTLS)", strings.ToUpper(info.Connection.Protocol))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "TLS version:  %s\n", info.Connection.TLSVersion)
	fmt.Fprintf(w, "Cipher suite: %s\n", info.Connection.CipherSuite)
	fmt.Fprintf(w, "SNI used:     %s\n", info.Connection.SNI)
	fmt.Fprintf(w, "Verified:     %s\n", cert.ColorBool(info.Connection.Verified))

	if !info.Connection.Verified && info.Connection.VerifyError != "" {
		fmt.Fprintf(w, "Verify error: %s\n", info.Connection.VerifyError)
	}
	fmt.Fprintln(w)

	printCertText("Leaf certificate", info.Leaf, w)

	if len(info.Chain) > 0 {
		fmt.Fprintln(w, "\nPeer chain (as presented):")
		for _, entry := range info.Chain {
			fmt.Fprintf(w, "  [%d] Subject: %s\n", entry.Index, entry.Subject)
			fmt.Fprintf(w, "      Issuer:  %s\n", entry.Issuer)
		}
	}

	fmt.Fprintf(w, "\nExpiry: %s (%d days left)\n", info.Expiry.NotAfter, info.Expiry.DaysLeft)
	return nil
}

func printCertText(title string, c cert.Certificate, w io.Writer) {
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, strings.Repeat("-", len(title)))
	fmt.Fprintf(w, "Subject:        %s\n", c.Subject)
	fmt.Fprintf(w, "Issuer:         %s\n", c.Issuer)
	fmt.Fprintf(w, "Serial:         %s\n", c.SerialNumber)
	fmt.Fprintf(w, "Valid from:     %s\n", c.NotBefore)
	fmt.Fprintf(w, "Valid until:    %s\n", c.NotAfter)
	fmt.Fprintf(w, "Signature algo: %s\n", c.SignatureAlgo)
	fmt.Fprintf(w, "Public key:     %s\n", c.PublicKey)

	if len(c.DNSNames) > 0 {
		fmt.Fprintf(w, "SAN DNS:        %s\n", strings.Join(c.DNSNames, ", "))
	}
	if len(c.IPAddresses) > 0 {
		fmt.Fprintf(w, "SAN IP:         %s\n", strings.Join(c.IPAddresses, ", "))
	}
	if len(c.EmailAddresses) > 0 {
		fmt.Fprintf(w, "SAN Email:      %s\n", strings.Join(c.EmailAddresses, ", "))
	}
	if len(c.URIs) > 0 {
		fmt.Fprintf(w, "SAN URI:        %s\n", strings.Join(c.URIs, ", "))
	}

	fmt.Fprintf(w, "Is CA:          %v\n", c.IsCA)
	if len(c.ExtKeyUsage) > 0 {
		fmt.Fprintf(w, "ExtKeyUsage:    %s\n", strings.Join(c.ExtKeyUsage, ", "))
	}
}
