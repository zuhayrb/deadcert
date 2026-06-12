package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test fixtures: a fabricated, self-signed cert with a controlled NotAfter,
// served by a local TLS listener. No real network access required, matching
// section 2.2 of the LDD.
// ---------------------------------------------------------------------------

// generateCert returns a self-signed certificate for 127.0.0.1 valid from
// notBefore to notAfter. The caller controls expiry entirely.
func generateCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

// startTLSServer starts a TLS listener on 127.0.0.1 presenting cert, accepts
// connections, completes the handshake, then holds briefly before closing.
// Returns the port and a cleanup function.
func startTLSServer(t *testing.T, cert tls.Certificate) (port int, cleanup func()) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("start TLS listener: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port, func() { ln.Close() }
}

// startHangingServer accepts TCP connections but never completes a TLS
// handshake — used to test --timeout behavior.
func startHangingServer(t *testing.T) (port int, cleanup func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start TCP listener: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and hold the connection open without responding,
			// so the client's TLS handshake stalls until its timeout fires.
			_ = conn
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port, func() { ln.Close() }
}

// freePortNoListener returns a port number with nothing listening on it,
// for testing the connection-refused path.
func freePortNoListener(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // release immediately; nothing will be listening
	return port
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCheckDomain_OK(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cert := generateCert(t, time.Now().Add(-time.Hour), notAfter)
	port, cleanup := startTLSServer(t, cert)
	defer cleanup()

	r := CheckDomain("127.0.0.1", port, 2*time.Second, 30)

	if r.Status != StatusOK {
		t.Fatalf("Status = %v, want StatusOK (message: %s)", r.Status, r.Message)
	}
	if r.Domain != "127.0.0.1" {
		t.Errorf("Domain = %q, want %q", r.Domain, "127.0.0.1")
	}
	if r.Port != port {
		t.Errorf("Port = %d, want %d", r.Port, port)
	}
	if r.DaysLeft < 88 || r.DaysLeft > 90 {
		t.Errorf("DaysLeft = %d, want ~89", r.DaysLeft)
	}
	if !r.ExpiresAt.Equal(notAfter.Truncate(time.Second)) && r.ExpiresAt.Sub(notAfter).Abs() > time.Second {
		t.Errorf("ExpiresAt = %v, want ~%v", r.ExpiresAt, notAfter)
	}
	if r.Message == "" {
		t.Error("Message is empty, want non-empty")
	}
}

func TestCheckDomain_Warning(t *testing.T) {
	notAfter := time.Now().Add(10 * 24 * time.Hour)
	cert := generateCert(t, time.Now().Add(-time.Hour), notAfter)
	port, cleanup := startTLSServer(t, cert)
	defer cleanup()

	r := CheckDomain("127.0.0.1", port, 2*time.Second, 30) // warnDays > daysLeft

	if r.Status != StatusWarning {
		t.Fatalf("Status = %v, want StatusWarning (message: %s)", r.Status, r.Message)
	}
	if r.DaysLeft < 8 || r.DaysLeft > 10 {
		t.Errorf("DaysLeft = %d, want ~9-10", r.DaysLeft)
	}
}

// TestCheckDomain_WarnDaysBoundary locks in the documented behavior at
// daysLeft == warnDays: the condition is "<=", so the boundary itself
// triggers a warning, not OK. (DR-007 area: deterministic thresholds.)
func TestCheckDomain_WarnDaysBoundary(t *testing.T) {
	// 5 days out, with truncation this lands daysLeft at 4 or 5 depending on
	// exact timing; either way warnDays=5 must catch it ("<=").
	notAfter := time.Now().Add(5*24*time.Hour + time.Minute)
	cert := generateCert(t, time.Now().Add(-time.Hour), notAfter)
	port, cleanup := startTLSServer(t, cert)
	defer cleanup()

	r := CheckDomain("127.0.0.1", port, 2*time.Second, 5)

	if r.Status != StatusWarning {
		t.Fatalf("Status = %v, want StatusWarning at boundary (daysLeft=%d, warnDays=5)", r.Status, r.DaysLeft)
	}
}

func TestCheckDomain_Expired(t *testing.T) {
	notAfter := time.Now().Add(-30 * 24 * time.Hour) // expired 30 days ago
	notBefore := notAfter.Add(-365 * 24 * time.Hour)
	cert := generateCert(t, notBefore, notAfter)
	port, cleanup := startTLSServer(t, cert)
	defer cleanup()

	r := CheckDomain("127.0.0.1", port, 2*time.Second, 30)

	if r.Status != StatusExpired {
		t.Fatalf("Status = %v, want StatusExpired (message: %s)", r.Status, r.Message)
	}
	if r.DaysLeft >= 0 {
		t.Errorf("DaysLeft = %d, want negative for a cert expired 30 days ago", r.DaysLeft)
	}
	if r.Message == "" {
		t.Error("Message is empty, want non-empty")
	}
}

// TestCheckDomain_ExpiredWithinOneDay documents a truncation edge case:
// Go's int() conversion truncates toward zero, so a cert that expired less
// than 24h ago produces DaysLeft == 0, not -1. Status is still StatusExpired
// because the time.Now().After(NotAfter) check is exact regardless of
// truncation. This test locks in the actual behavior so a future change to
// the truncation logic is a deliberate decision, not an accident.
func TestCheckDomain_ExpiredWithinOneDay(t *testing.T) {
	notAfter := time.Now().Add(-12 * time.Hour) // expired 12 hours ago
	notBefore := notAfter.Add(-365 * 24 * time.Hour)
	cert := generateCert(t, notBefore, notAfter)
	port, cleanup := startTLSServer(t, cert)
	defer cleanup()

	r := CheckDomain("127.0.0.1", port, 2*time.Second, 30)

	if r.Status != StatusExpired {
		t.Fatalf("Status = %v, want StatusExpired (message: %s)", r.Status, r.Message)
	}
	if r.DaysLeft != 0 {
		t.Errorf("DaysLeft = %d, want 0 (truncation toward zero for <24h expired)", r.DaysLeft)
	}
}

// TestCheckDomain_WarnDaysZero exercises OQ-1/DR-008: --warn-days 0 must not
// turn a healthy, far-from-expiry cert into a warning, but must not suppress
// an actually-expired cert either.
func TestCheckDomain_WarnDaysZero(t *testing.T) {
	t.Run("healthy cert stays OK", func(t *testing.T) {
		notAfter := time.Now().Add(100 * 24 * time.Hour)
		cert := generateCert(t, time.Now().Add(-time.Hour), notAfter)
		port, cleanup := startTLSServer(t, cert)
		defer cleanup()

		r := CheckDomain("127.0.0.1", port, 2*time.Second, 0)
		if r.Status != StatusOK {
			t.Fatalf("Status = %v, want StatusOK with warnDays=0 (message: %s)", r.Status, r.Message)
		}
	})

	t.Run("expired cert still reported expired", func(t *testing.T) {
		notAfter := time.Now().Add(-30 * 24 * time.Hour)
		notBefore := notAfter.Add(-365 * 24 * time.Hour)
		cert := generateCert(t, notBefore, notAfter)
		port, cleanup := startTLSServer(t, cert)
		defer cleanup()

		r := CheckDomain("127.0.0.1", port, 2*time.Second, 0)
		if r.Status != StatusExpired {
			t.Fatalf("Status = %v, want StatusExpired with warnDays=0 (message: %s)", r.Status, r.Message)
		}
	})
}

// TestCheckDomain_NotYetValid covers DR-019: a cert whose NotBefore is in
// the future. With InsecureSkipVerify, the handshake succeeds and
// CheckDomain must classify this itself rather than letting the TLS layer
// reject it as a generic handshake error.
func TestCheckDomain_NotYetValid(t *testing.T) {
	notBefore := time.Now().Add(24 * time.Hour) // valid starting tomorrow
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	cert := generateCert(t, notBefore, notAfter)
	port, cleanup := startTLSServer(t, cert)
	defer cleanup()

	r := CheckDomain("127.0.0.1", port, 2*time.Second, 30)

	if r.Status != StatusError {
		t.Fatalf("Status = %v, want StatusError for not-yet-valid cert (message: %s)", r.Status, r.Message)
	}
	if r.Message == "" {
		t.Error("Message is empty, want a not-yet-valid description")
	}
}

// TestCheckDomain_ConnectionRefused covers P2: an unreachable domain is a
// valid result, not a panic or an error return.
func TestCheckDomain_ConnectionRefused(t *testing.T) {
	port := freePortNoListener(t)

	r := CheckDomain("127.0.0.1", port, 2*time.Second, 30)

	if r.Status != StatusError {
		t.Fatalf("Status = %v, want StatusError (message: %s)", r.Status, r.Message)
	}
	if r.Domain != "127.0.0.1" {
		t.Errorf("Domain = %q, want %q", r.Domain, "127.0.0.1")
	}
	if r.Port != port {
		t.Errorf("Port = %d, want %d", r.Port, port)
	}
	if !r.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero value on error", r.ExpiresAt)
	}
	if r.DaysLeft != 0 {
		t.Errorf("DaysLeft = %d, want 0 on error", r.DaysLeft)
	}
	if r.Message == "" {
		t.Error("Message is empty, want a description of the connection failure")
	}
}

// TestCheckDomain_Timeout covers per-domain timeout behavior (OQ-3/DR-010):
// a server that never completes the handshake must cause CheckDomain to
// return StatusError within roughly the configured timeout, not hang.
func TestCheckDomain_Timeout(t *testing.T) {
	port, cleanup := startHangingServer(t)
	defer cleanup()

	timeout := 100 * time.Millisecond
	start := time.Now()
	r := CheckDomain("127.0.0.1", port, timeout, 30)
	elapsed := time.Since(start)

	if r.Status != StatusError {
		t.Fatalf("Status = %v, want StatusError (message: %s)", r.Status, r.Message)
	}
	// Allow generous slack for scheduler jitter, but it must not hang.
	if elapsed > 2*time.Second {
		t.Errorf("CheckDomain took %v with a %v timeout, want roughly that order of magnitude", elapsed, timeout)
	}
	if r.Message == "" {
		t.Error("Message is empty, want a timeout description")
	}
}
