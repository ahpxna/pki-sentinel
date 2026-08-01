// Package canary runs an ephemeral in-process TLS server that serves a
// canary certificate for exactly one probe cycle, with optional OCSP
// stapling in three modes: on, off, and stale.
package canary

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// StaplingMode controls whether/how the server staples an OCSP response.
type StaplingMode string

const (
	// StaplingOn staples a freshly fetched OCSP response reflecting the
	// certificate's current (possibly revoked) status.
	StaplingOn StaplingMode = "on"
	// StaplingOff serves no stapled response at all.
	StaplingOff StaplingMode = "off"
	// StaplingStale staples a response fetched BEFORE revocation — exactly
	// how a real attacker would extend a compromised cert's life. First-class
	// test case, not an afterthought.
	StaplingStale StaplingMode = "stale"
)

// hostsMu serializes /etc/hosts edits across cycles: only one cycle may
// hold an entry at a time, since all probe subprocesses share one
// /etc/hosts inside a single container.
var hostsMu sync.Mutex

// Server is a single-cycle ephemeral TLS canary endpoint.
type Server struct {
	Hostname string // e.g. canary-<uuid>.canary.internal
	Port     int

	ln       net.Listener
	srv      *tlsServer
	hostsAdded bool
}

type tlsServer struct {
	config *tls.Config
}

// Start binds to 127.0.0.1:<random free port>, adds a temporary /etc/hosts
// entry for hostname, and begins serving certPEM/keyPEM with the given
// OCSP staple (may be nil for StaplingOff).
func Start(hostname string, certPEM, keyPEM []byte, staple []byte) (*Server, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("canary: loading keypair: %w", err)
	}
	if staple != nil {
		cert.OCSPStaple = staple
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("canary: listening: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	hostsMu.Lock()
	if err := addHostsEntry(hostname); err != nil {
		hostsMu.Unlock()
		_ = ln.Close()
		return nil, fmt.Errorf("canary: adding /etc/hosts entry: %w", err)
	}

	s := &Server{
		Hostname:   hostname,
		Port:       port,
		ln:         ln,
		hostsAdded: true,
		srv: &tlsServer{config: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}},
	}
	hostsMu.Unlock()

	go s.serve()
	return s, nil
}

func (s *Server) serve() {
	tlsLn := tls.NewListener(s.ln, s.srv.config)
	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			return // listener closed
		}
		go func(c net.Conn) {
			defer c.Close()
			// Minimal HTTP/1.1 response; profiles only care about the TLS
			// handshake and revocation-check outcome, not response body.
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}(conn)
	}
}

// Close stops the listener and removes the temporary /etc/hosts entry.
func (s *Server) Close() error {
	err := s.ln.Close()
	if s.hostsAdded {
		hostsMu.Lock()
		_ = removeHostsEntry(s.Hostname)
		hostsMu.Unlock()
	}
	return err
}

func addHostsEntry(hostname string) error {
	f, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("127.0.0.1 %s\n", hostname))
	return err
}

func removeHostsEntry(hostname string) error {
	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	kept := lines[:0]
	needle := "127.0.0.1 " + hostname
	for _, line := range lines {
		if strings.TrimSpace(line) == needle {
			continue
		}
		kept = append(kept, line)
	}
	return os.WriteFile("/etc/hosts", []byte(strings.Join(kept, "\n")), 0o644)
}

// WaitReachable polls the canary endpoint until it accepts a raw TCP
// connection or ctx is done. Used by the runner's pre-flight guard.
func WaitReachable(ctx context.Context, addr string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}
