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
	"os"
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

func canWriteEtcHosts() bool {
	f, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func TestServerStartAndConnect(t *testing.T) {
	if !canWriteEtcHosts() {
		t.Skip("no permission to write /etc/hosts in this environment (requires root in CI/container)")
	}
	certPEM, keyPEM := selfSignedPEM(t, "canary-test.canary.internal")

	s, err := Start("canary-test.canary.internal", certPEM, keyPEM, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
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
}

func TestWaitReachableTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listening now

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := WaitReachable(ctx, addr); err == nil {
		t.Fatal("expected WaitReachable to time out")
	}
}
