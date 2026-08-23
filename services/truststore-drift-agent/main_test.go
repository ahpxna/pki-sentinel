package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
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

func testCertificate(t *testing.T, commonName string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		Subject:                 pkix.Name{CommonName: commonName},
		RawSubjectPublicKeyInfo: spki,
		NotAfter:                notAfter,
	}
}

func TestEvaluateTrustStoreDetectsAllDriftClasses(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	expired := testCertificate(t, "Expected A", now.Add(-time.Hour))
	expectedB := testCertificate(t, "Expected B", now.Add(365*24*time.Hour))
	changedB := testCertificate(t, "Expected B", now.Add(7*24*time.Hour))
	unknown := testCertificate(t, "Unknown C", now.Add(365*24*time.Hour))
	baseline := Baseline{Roots: []RootEntry{
		{Subject: expired.Subject.String(), SPKIHash: spkiHash(expired)},
		{Subject: expectedB.Subject.String(), SPKIHash: spkiHash(expectedB)},
	}}

	result := evaluateTrustStore(baseline, []*x509.Certificate{expired, changedB, unknown}, now)
	if result.UnknownRoots != 2 || result.ChangedRoots != 1 || result.MissingRoots != 1 {
		t.Fatalf("unexpected drift counts: %+v", result)
	}
	if result.ExpiredRoots != 1 || result.ExpiringRoots != 1 {
		t.Fatalf("unexpected expiry counts: %+v", result)
	}
	if !result.BaselineValid || !result.ScanSuccess {
		t.Fatalf("expected valid successful scan: %+v", result)
	}
}

func TestPrometheusTextContainsBoundedMetrics(t *testing.T) {
	text := prometheusText(ScanResult{
		UnknownRoots: 2, MissingRoots: 1, BaselineValid: true, ScanSuccess: true,
		LastScan: time.Unix(123, 0),
	})
	for _, want := range []string{
		"pki_truststore_unknown_roots 2",
		"pki_truststore_missing_roots 1",
		"pki_truststore_baseline_valid 1",
		"pki_truststore_last_scan_timestamp_seconds 123",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q:\n%s", want, text)
		}
	}
}
