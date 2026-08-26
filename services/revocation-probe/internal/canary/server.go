// Package canary runs an ephemeral in-process TLS server that serves a
// canary certificate for exactly one probe cycle, with optional OCSP
// stapling in three modes: on, off, and stale.
package canary

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// StaplingMode controls whether/how the server staples an OCSP response.
type StaplingMode string

const (
	connectionDeadline = 5 * time.Second

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

// Server is a single-cycle ephemeral TLS canary endpoint.
type Server struct {
	Hostname string // e.g. canary-<uuid>.canary.internal
	Port     int

	ln  net.Listener
	srv *tlsServer

	connMu     sync.Mutex
	conns      map[net.Conn]struct{}
	handlers   sync.WaitGroup
	acceptDone chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

type tlsServer struct {
	mu     sync.RWMutex
	cert   *tls.Certificate
	config *tls.Config
}

// Start binds to 127.0.0.1:<random free port> and begins serving
// certPEM/keyPEM with the given OCSP staple (may be nil for StaplingOff).
func Start(hostname string, certPEM, keyPEM []byte, staple []byte) (*Server, error) {
	return StartOn("127.0.0.1", hostname, certPEM, keyPEM, staple)
}

// StartOn binds to bindHost:<random free port>. Containerized client
// executors use 0.0.0.0 here and reach the service through its Compose DNS
// name; local and integration callers retain the loopback-only default.
func StartOn(bindHost, hostname string, certPEM, keyPEM []byte, staple []byte) (*Server, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("canary: loading keypair: %w", err)
	}
	if staple != nil {
		cert.OCSPStaple = staple
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(bindHost, "0"))
	if err != nil {
		return nil, fmt.Errorf("canary: listening: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	tlsSrv := &tlsServer{cert: &cert}
	tlsSrv.config = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			tlsSrv.mu.RLock()
			defer tlsSrv.mu.RUnlock()
			return tlsSrv.cert, nil
		},
	}

	s := &Server{
		Hostname:   hostname,
		Port:       port,
		ln:         ln,
		srv:        tlsSrv,
		conns:      make(map[net.Conn]struct{}),
		acceptDone: make(chan struct{}),
	}

	go s.serve()
	return s, nil
}

func (s *Server) serve() {
	defer close(s.acceptDone)
	tlsLn := tls.NewListener(s.ln, s.srv.config)
	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			return // listener closed
		}

		s.connMu.Lock()
		s.conns[conn] = struct{}{}
		s.handlers.Add(1)
		s.connMu.Unlock()

		go func(c net.Conn) {
			defer s.handlers.Done()
			defer func() {
				s.connMu.Lock()
				delete(s.conns, c)
				s.connMu.Unlock()
				_ = c.Close()
			}()

			// tls.Listener performs the handshake lazily on the first I/O. A
			// peer that opens TCP and never sends ClientHello must not pin an
			// assurance goroutine or file descriptor indefinitely.
			_ = c.SetDeadline(time.Now().Add(connectionDeadline))
			// Minimal HTTP/1.1 response; profiles only care about the TLS
			// handshake and revocation-check outcome, not response body.
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}(conn)
	}
}

// SetOCSPStaple atomically replaces the staple used by future TLS handshakes.
func (s *Server) SetOCSPStaple(staple []byte) {
	s.srv.mu.Lock()
	defer s.srv.mu.Unlock()
	cert := *s.srv.cert
	cert.OCSPStaple = append([]byte(nil), staple...)
	s.srv.cert = &cert
}

// Close stops the listener, closes every accepted connection, and waits for
// all TLS handlers to exit. It is safe to call more than once.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.ln.Close()
		// Once the accept loop exits no new connection can be added to conns,
		// so the snapshot below covers every accepted peer.
		<-s.acceptDone

		s.connMu.Lock()
		active := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			active = append(active, conn)
		}
		s.connMu.Unlock()
		for _, conn := range active {
			_ = conn.Close()
		}
		s.handlers.Wait()
	})
	return s.closeErr
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
