package cert

import (
	"crypto/x509"
	"time"
)

// Verify verifies the certificate chain and hostname
func Verify(peer []*x509.Certificate, serverName string) (bool, error) {
	if len(peer) == 0 {
		return false, nil
	}

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
