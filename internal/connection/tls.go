package connection

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/grimne/certcheck/internal/cert"
	"github.com/grimne/certcheck/internal/config"
)

// FetchCertInfo fetches certificate information from target
func FetchCertInfo(target string, cfg *config.Config) (*cert.Info, error) {
	var conn *tls.Conn
	var err error

	if cfg.StartTLS != config.ProtocolNone {
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

	verified, verifyErr := cert.Verify(state.PeerCertificates, cfg.ServerName)

	info := &cert.Info{
		Connection: cert.ConnectionInfo{
			Target:      target,
			TLSVersion:  cert.TLSVersion(state.Version),
			CipherSuite: tls.CipherSuiteName(state.CipherSuite),
			SNI:         cfg.ServerName,
			Verified:    verified,
		},
		Leaf:   cert.BuildCertificate(state.PeerCertificates[0]),
		Expiry: cert.BuildExpiryInfo(state.PeerCertificates[0]),
	}

	if cfg.StartTLS != config.ProtocolNone {
		info.Connection.Protocol = string(cfg.StartTLS)
	}

	if !verified && verifyErr != nil {
		info.Connection.VerifyError = verifyErr.Error()
	}

	if cfg.PrintChain {
		info.Chain = make([]cert.ChainEntry, len(state.PeerCertificates))
		for i, c := range state.PeerCertificates {
			info.Chain[i] = cert.ChainEntry{
				Index:   i,
				Subject: cert.FormatDN(c.Subject),
				Issuer:  cert.FormatDN(c.Issuer),
			}
		}
	}

	return info, nil
}

func dialDirectTLS(target string, cfg *config.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	tlsConfig := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connect failed: %w", err)
	}
	return conn, nil
}

func dialStartTLS(target string, cfg *config.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.Timeout}

	netConn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}

	if err := performStartTLS(netConn, cfg.StartTLS, cfg.ServerName); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("STARTTLS handshake failed: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         cfg.ServerName,
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

func performStartTLS(conn net.Conn, proto config.StartTLSProtocol, serverName string) error {
	switch proto {
	case config.ProtocolSMTP:
		return startTLSSMTP(conn, serverName)
	case config.ProtocolIMAP:
		return startTLSIMAP(conn)
	case config.ProtocolPOP3:
		return startTLSPOP3(conn)
	case config.ProtocolFTP:
		return startTLSFTP(conn)
	default:
		return fmt.Errorf("unsupported STARTTLS protocol: %s", proto)
	}
}
