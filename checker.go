package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Status represents the health state of a single domain's TLS certificate.
// Every call to CheckDomain produces exactly one of these values — including
// network failures, which are results rather than exceptions (P2).
type Status int

const (
	StatusOK      Status = iota // cert is valid and not expiring soon
	StatusWarning               // cert expires within --warn-days
	StatusExpired               // cert has already expired
	StatusError                 // domain unreachable or TLS handshake failed
)

// Result is the single return value of CheckDomain. It carries everything
// output.go needs to render either human or JSON output. CheckDomain never
// writes to stdout or stderr — callers own all output (DR-003).
type Result struct {
	Domain    string
	Port      int
	Status    Status
	ExpiresAt time.Time // zero value when Status is StatusError
	DaysLeft  int       // negative when already expired; 0 when Status is StatusError
	Message   string    // human-readable detail; always set
}

// CheckDomain dials domain:port, completes a TLS handshake, inspects the leaf
// certificate, and returns a Result. It never panics on external failure (P2).
// timeout is applied per-domain (OQ-3 / DR-010).
//
// The function signature is the public contract described in section 2.2 of
// the LDD. Tests point this at a local TLS server with a fabricated cert.
func CheckDomain(domain string, port int, timeout time.Duration, warnDays int) Result {
	addr := fmt.Sprintf("%s:%d", domain, port)

	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{
		// ServerName is still sent for SNI so the server can select the
		// right cert for virtual hosting — but we do NOT rely on it, or on
		// chain trust, for our result (DR-019).
		ServerName: domain,
		// InsecureSkipVerify disables Go's automatic x509.Verify(), which
		// includes the expiry check. Without this, an expired cert causes
		// the handshake itself to fail with a generic TLS error, and
		// CheckDomain could never distinguish "expired" from "unreachable"
		// (DR-019). We perform our own expiry check below using the leaf
		// cert's NotBefore/NotAfter. Hostname and CA-trust validation are
		// intentionally out of scope (P4: this tool checks expiry, not
		// general certificate validity).
		InsecureSkipVerify: true,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
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
	case now.Before(leaf.NotBefore):
		// Not yet valid — reported as StatusError rather than a dedicated
		// status, since it's an out-of-scope misconfiguration (P4) and
		// adding a new Status would ripple into output.go's switch
		// statements for a case the LDD does not call out. See note in the
		// commit/DR discussion: candidate for its own status if this proves
		// common in practice.
		return Result{
			Domain:  domain,
			Port:    port,
			Status:  StatusError,
			Message: fmt.Sprintf("certificate is not yet valid (valid from %s)", leaf.NotBefore.Format("2006-01-02")),
		}
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
