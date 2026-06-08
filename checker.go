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
}
