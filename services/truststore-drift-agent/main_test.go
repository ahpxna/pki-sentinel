package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func TestSPKIHashIsStableAndKeySpecific(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki1, err := x509.MarshalPKIXPublicKey(&key1.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	spki2, err := x509.MarshalPKIXPublicKey(&key2.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert1 := &x509.Certificate{RawSubjectPublicKeyInfo: spki1}
	cert2 := &x509.Certificate{RawSubjectPublicKeyInfo: spki2}
	hash1 := spkiHash(cert1)
	hash1Again := spkiHash(cert1)
	if hash1 != hash1Again {
		t.Fatal("same public key produced different hashes")
	}
	if hash1 == spkiHash(cert2) {
		t.Fatal("different public keys produced the same hash")
	}
}

func TestParseFlag(t *testing.T) {
	if got := parseFlag([]string{"-b", "custom.json"}, "-b", "default.json"); got != "custom.json" {
		t.Fatalf("got %q", got)
	}
	if got := parseFlag(nil, "-b", "default.json"); got != "default.json" {
		t.Fatalf("got %q", got)
	}
}

func TestBaselineSignatureRejectsTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	baseline := Baseline{
		GeneratedAt: time.Unix(1, 0).UTC(),
		Roots:       []RootEntry{{Subject: "CN=Expected", SPKIHash: "abc"}},
	}
	if err := signBaseline(&baseline, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := verifyBaseline(baseline, publicKey); err != nil {
		t.Fatalf("valid baseline rejected: %v", err)
	}
	baseline.Roots[0].Subject = "CN=Tampered"
	if err := verifyBaseline(baseline, publicKey); err == nil {
		t.Fatal("tampered baseline passed signature verification")
	}
}
