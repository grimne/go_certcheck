package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/grimne/certcheck/internal/cert"
)

func writeText(info *cert.Info, w io.Writer) error {
	if _, err := fmt.Fprintf(w, "Connected to: %s", info.Connection.Target); err != nil {
		return err
	}
	if info.Connection.Protocol != "" {
		if _, err := fmt.Fprintf(w, " (via %s STARTTLS)", strings.ToUpper(info.Connection.Protocol)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "TLS version:  %s\n", info.Connection.TLSVersion); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Cipher suite: %s\n", info.Connection.CipherSuite); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "SNI used:     %s\n", info.Connection.SNI); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Verified:     %s\n", cert.ColorBool(info.Connection.Verified)); err != nil {
		return err
	}

	if !info.Connection.Verified && info.Connection.VerifyError != "" {
		if _, err := fmt.Fprintf(w, "Verify error: %s\n", info.Connection.VerifyError); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if err := printCertText("Leaf certificate", info.Leaf, w); err != nil {
		return err
	}

	if len(info.Chain) > 0 {
		if _, err := fmt.Fprintln(w, "\nPeer chain (as presented):"); err != nil {
			return err
		}
		for _, entry := range info.Chain {
			if _, err := fmt.Fprintf(w, "  [%d] Subject: %s\n", entry.Index, entry.Subject); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "      Issuer:  %s\n", entry.Issuer); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintf(w, "\nExpiry: %s (%d days left)\n", info.Expiry.NotAfter, info.Expiry.DaysLeft); err != nil {
		return err
	}
	return nil
}

func printCertText(title string, c cert.Certificate, w io.Writer) error {
	if _, err := fmt.Fprintln(w, title); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("-", len(title))); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Subject:        %s\n", c.Subject); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Issuer:         %s\n", c.Issuer); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Serial:         %s\n", c.SerialNumber); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Valid from:     %s\n", c.NotBefore); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Valid until:    %s\n", c.NotAfter); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Signature algo: %s\n", c.SignatureAlgo); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Public key:     %s\n", c.PublicKey); err != nil {
		return err
	}

	if len(c.DNSNames) > 0 {
		if _, err := fmt.Fprintf(w, "SAN DNS:        %s\n", strings.Join(c.DNSNames, ", ")); err != nil {
			return err
		}
	}
	if len(c.IPAddresses) > 0 {
		if _, err := fmt.Fprintf(w, "SAN IP:         %s\n", strings.Join(c.IPAddresses, ", ")); err != nil {
			return err
		}
	}
	if len(c.EmailAddresses) > 0 {
		if _, err := fmt.Fprintf(w, "SAN Email:      %s\n", strings.Join(c.EmailAddresses, ", ")); err != nil {
			return err
		}
	}
	if len(c.URIs) > 0 {
		if _, err := fmt.Fprintf(w, "SAN URI:        %s\n", strings.Join(c.URIs, ", ")); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "Is CA:          %v\n", c.IsCA); err != nil {
		return err
	}
	if len(c.ExtKeyUsage) > 0 {
		if _, err := fmt.Fprintf(w, "ExtKeyUsage:    %s\n", strings.Join(c.ExtKeyUsage, ", ")); err != nil {
			return err
		}
	}
	return nil
}
