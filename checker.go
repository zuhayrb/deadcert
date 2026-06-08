package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type Status int

const (
	StatusOK      Status = iota // cert is valid  and not expiring soon
	StatusWarning               // cert expires within --warn-days
	StatusExpired               // cert has already expired
	StatusError                 // domain unreachable or TLS handshake failed
)

// Result carries everything output.go needs to render either human or JSON output
type Result struct {
	Domain    string
	Port      int
	Status    Status
	ExpiresAt time.Time // Zero value when Status is StatusError
	DaysLeft  int       // Negative when already expired; 0 when Status is StatusError
	Message   string    // Human-readable detail; always set
}

func CheckDomain(domain string, port int, timeout time.Duration, warnDays int) Result {
	addr := fmt.Sprintf("%s:%d", domain, port)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		// ServerName is required when the address is already host:port so that
		// SNI is sent correctly and the cert is validated against the domain
		// name rather than the IP address that the dialer resolved to.
		ServerName: domain,
	})
	if err != nil {
		return Result{
			Domain:  domain,
			Port:    port,
			Status:  StatusError,
			Message: err.Error(),
		}
	}
	defer conn.Close()

	// PeerCertificates[0] is always the leaf cert (section 2.5 of the LDD).
	// The slice is guaranteed non-empty after a successful DialWithDialer
	// because the TLS handshake verifies the server presented at least one cert.
	leaf := conn.ConnectionState().PeerCertificates[0]

	now := time.Now()
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)

	switch {
	case now.After(leaf.NotAfter):
		return Result{
			Domain:    domain,
			Port:      port,
			Status:    StatusExpired,
			ExpiresAt: leaf.NotAfter,
			DaysLeft:  daysLeft, // negative
			Message:   fmt.Sprintf("certificate expired %s", leaf.NotAfter.Format("2006-01-02")),
		}
	case daysLeft <= warnDays:
		return Result{
			Domain:    domain,
			Port:      port,
			Status:    StatusWarning,
			ExpiresAt: leaf.NotAfter,
			DaysLeft:  daysLeft,
			Message:   fmt.Sprintf("certificate expires in %d days (%s)", daysLeft, leaf.NotAfter.Format("2006-01-02")),
		}
	default:
		return Result{
			Domain:    domain,
			Port:      port,
			Status:    StatusOK,
			ExpiresAt: leaf.NotAfter,
			DaysLeft:  daysLeft,
			Message:   fmt.Sprintf("certificate valid for %d days (%s)", daysLeft, leaf.NotAfter.Format("2006-01-02")),
		}
	}
}
