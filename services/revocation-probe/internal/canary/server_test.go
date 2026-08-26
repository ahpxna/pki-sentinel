package canary

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedPEM generates a throwaway self-signed EC certificate for tests.
func selfSignedPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestServerStartAndConnect(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t, "canary-test.canary.internal")

	s, err := Start("canary-test.canary.internal", certPEM, keyPEM, nil)
	if err != nil {
		t.Skipf("loopback listeners are unavailable in this environment: %v", err)
	}
	defer s.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", s.Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := WaitReachable(ctx, addr); err != nil {
		t.Fatalf("WaitReachable: %v", err)
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("expected at least one peer certificate")
	}
	if state.PeerCertificates[0].Subject.CommonName != "canary-test.canary.internal" {
		t.Fatalf("unexpected CN: %s", state.PeerCertificates[0].Subject.CommonName)
	}

	s.SetOCSPStaple([]byte("updated-staple"))
	conn2, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("second tls.Dial: %v", err)
	}
	defer conn2.Close()
	if got := string(conn2.ConnectionState().OCSPResponse); got != "updated-staple" {
		t.Fatalf("expected updated OCSP staple, got %q", got)
	}
}

func TestWaitReachableTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners are unavailable in this environment: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listening now

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := WaitReachable(ctx, addr); err == nil {
		t.Fatal("expected WaitReachable to time out")
	}
}

func TestCloseTerminatesStalledTLSHandshakes(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t, "stalled.canary.internal")
	s, err := Start("stalled.canary.internal", certPEM, keyPEM, nil)
	if err != nil {
		t.Skipf("loopback listeners are unavailable in this environment: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", s.Port)
	const clients = 12
	connections := make([]net.Conn, 0, clients)
	for i := 0; i < clients; i++ {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial stalled client %d: %v", i, err)
		}
		connections = append(connections, conn)
	}
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()

	deadline := time.Now().Add(time.Second)
	for {
		s.connMu.Lock()
		active := len(s.conns)
		s.connMu.Unlock()
		if active == clients {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server accepted %d/%d stalled clients", active, clients)
		}
		time.Sleep(10 * time.Millisecond)
	}

	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked on stalled TLS handshakes")
	}

	s.connMu.Lock()
	active := len(s.conns)
	s.connMu.Unlock()
	if active != 0 {
		t.Fatalf("%d accepted connections remain after Close", active)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
