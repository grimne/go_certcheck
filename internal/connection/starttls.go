package connection

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func startTLSSMTP(conn net.Conn, serverName string) error {
	reader := bufio.NewReader(conn)

	if _, err := readSMTPResponse(reader, "220"); err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", serverName); err != nil {
		return err
	}
	if _, err := readSMTPResponse(reader, "250"); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	if _, err := readSMTPResponse(reader, "220"); err != nil {
		return fmt.Errorf("STARTTLS: %w", err)
	}

	return nil
}

func startTLSIMAP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	if _, err := reader.ReadString('\n'); err != nil {
		return fmt.Errorf("IMAP greeting: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "a001 STARTTLS\r\n"); err != nil {
		return err
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("STARTTLS response: %w", err)
	}
	if !strings.Contains(response, "OK") {
		return fmt.Errorf("STARTTLS not accepted: %s", strings.TrimSpace(response))
	}

	return nil
}

func startTLSPOP3(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("POP3 greeting: %w", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		return fmt.Errorf("bad POP3 greeting: %s", strings.TrimSpace(response))
	}

	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return err
	}

	response, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("STLS response: %w", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		return fmt.Errorf("STLS not accepted: %s", strings.TrimSpace(response))
	}

	return nil
}

func startTLSFTP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	if _, err := readFTPResponse(reader, "220"); err != nil {
		return fmt.Errorf("FTP greeting: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return err
	}

	if _, err := readFTPResponse(reader, "234"); err != nil {
		return fmt.Errorf("AUTH TLS: %w", err)
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
