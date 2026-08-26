package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestNativeMacOSTrustStoreFailsClosed(t *testing.T) {
	if err := nativeTrustStoreSupport("darwin"); err == nil || !strings.Contains(err.Error(), "effective trust settings") {
		t.Fatalf("native macOS certificate inventory was accepted: %v", err)
	}
	if err := nativeTrustStoreSupport("linux"); err != nil {
		t.Fatalf("linux trust store unexpectedly rejected: %v", err)
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

func TestBaselineStateRejectsRollback(t *testing.T) {
	dir := t.TempDir()
	statePath := dir + "/baseline.state"
	newer := Baseline{GeneratedAt: time.Now().UTC(), Sequence: 2, ExpiresAt: time.Now().Add(time.Hour)}
	if err := verifyAndAdvanceBaselineState(newer, statePath); err != nil {
		t.Fatal(err)
	}
	older := Baseline{GeneratedAt: time.Now().UTC(), Sequence: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := verifyAndAdvanceBaselineState(older, statePath); err == nil {
		t.Fatal("accepted a lower baseline sequence")
	}
}

func TestBaselineStateWriteIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "baseline.state")
	baseline := Baseline{GeneratedAt: time.Now().UTC(), Sequence: 3, ExpiresAt: time.Now().Add(time.Hour)}
	if err := verifyAndAdvanceBaselineState(baseline, statePath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("state mode=%#o, want 0600", got)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state BaselineState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("state is not valid JSON: %v", err)
	}
	if state.HighestSequence != baseline.Sequence || state.Digest == "" {
		t.Fatalf("unexpected persisted state: %+v", state)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".baseline.state.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary state files leaked: %v", matches)
	}
}

func TestBaselineStateRejectsEscapingSymlink(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.state")
	if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(stateDir, "baseline.state")
	if err := os.Symlink(outside, statePath); err != nil {
		t.Fatal(err)
	}
	baseline := Baseline{GeneratedAt: time.Now().UTC(), Sequence: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := verifyAndAdvanceBaselineState(baseline, statePath); err == nil {
		t.Fatal("escaping state symlink was accepted")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "sentinel" {
		t.Fatalf("outside file was modified: %q", data)
	}
}

func TestBaselineStateRequiresExistingParentDirectory(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "missing", "baseline.state")
	baseline := Baseline{GeneratedAt: time.Now().UTC(), Sequence: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := verifyAndAdvanceBaselineState(baseline, statePath); err == nil {
		t.Fatal("missing state parent directory was silently created")
	}
}

func TestBaselineStateSerializesConcurrentAdvance(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "baseline.state")
	now := time.Now().UTC()
	sequence1 := Baseline{GeneratedAt: now, Sequence: 1, ExpiresAt: now.Add(time.Hour)}
	if err := verifyAndAdvanceBaselineState(sequence1, statePath); err != nil {
		t.Fatal(err)
	}
	digest1, err := baselineDigest(sequence1)
	if err != nil {
		t.Fatal(err)
	}
	sequence2 := Baseline{GeneratedAt: now.Add(time.Second), Sequence: 2, PreviousDigest: digest1, ExpiresAt: now.Add(time.Hour)}
	digest2, err := baselineDigest(sequence2)
	if err != nil {
		t.Fatal(err)
	}
	sequence3 := Baseline{GeneratedAt: now.Add(2 * time.Second), Sequence: 3, PreviousDigest: digest2, ExpiresAt: now.Add(time.Hour)}

	enteredWrite := make(chan struct{})
	releaseWrite := make(chan struct{})
	seq2Done := make(chan error, 1)
	go func() {
		seq2Done <- verifyAndAdvanceBaselineStateWithHook(sequence2, statePath, func() {
			close(enteredWrite)
			<-releaseWrite
		})
	}()
	<-enteredWrite

	seq3Done := make(chan error, 1)
	go func() { seq3Done <- verifyAndAdvanceBaselineState(sequence3, statePath) }()
	select {
	case err := <-seq3Done:
		t.Fatalf("sequence 3 bypassed in-flight state transaction: %v", err)
	case <-time.After(50 * time.Millisecond):
		// Expected: the sequence-2 writer still owns the transaction lock.
	}
	close(releaseWrite)
	if err := <-seq2Done; err != nil {
		t.Fatalf("sequence 2 advance failed: %v", err)
	}
	if err := <-seq3Done; err != nil {
		t.Fatalf("sequence 3 advance failed after lock release: %v", err)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state BaselineState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.HighestSequence != 3 {
		t.Fatalf("final highest sequence=%d, want 3", state.HighestSequence)
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
		Raw:                     append([]byte(commonName+":"), spki...),
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

func TestCheckExitCodeFailsOnChangedRoots(t *testing.T) {
	if got := checkExitCode(ScanResult{ChangedRoots: 1}); got != 1 {
		t.Fatalf("changed root check exit code=%d, want 1", got)
	}
	if got := checkExitCode(ScanResult{}); got != 0 {
		t.Fatalf("clean check exit code=%d, want 0", got)
	}
}

func TestParseStrictBaselineRejectsAmbiguousOrUnknownJSON(t *testing.T) {
	for name, contents := range map[string]string{
		"unknown field":         `{"generated_at":"2026-01-01T00:00:00Z","roots":[],"signature":"x","future_policy":"ignore"}`,
		"duplicate key":         `{"generated_at":"2026-01-01T00:00:00Z","generated_at":"2026-01-02T00:00:00Z","roots":[],"signature":"x"}`,
		"second document":       `{"generated_at":"2026-01-01T00:00:00Z","roots":[],"signature":"x"} {}`,
		"duplicate certificate": `{"generated_at":"2026-01-01T00:00:00Z","roots":[{"subject":"A","spki_sha256":"one","cert_sha256":"same"},{"subject":"B","spki_sha256":"two","cert_sha256":"same"}],"signature":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseStrictBaseline([]byte(contents)); err == nil {
				t.Fatal("ambiguous baseline was accepted")
			}
		})
	}
}

func TestBaselinePermitsSharedSubjectOrSPKIWhenCertificatesDiffer(t *testing.T) {
	baseline := Baseline{Roots: []RootEntry{
		{Subject: "CN=Shared", SPKIHash: "shared-key", CertHash: "certificate-a"},
		{Subject: "CN=Shared", SPKIHash: "shared-key", CertHash: "certificate-b"},
	}}
	if err := validateBaseline(baseline); err != nil {
		t.Fatalf("valid distinct certificates rejected: %v", err)
	}
}

func TestEvaluateTrustStoreDetectsRemovedSameSPKISibling(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	certA := testCertificate(t, "Shared Key A", now.Add(365*24*time.Hour))
	certB := *certA
	certB.Subject = pkix.Name{CommonName: "Shared Key B"}
	certB.Raw = append([]byte("shared-key-b:"), certA.Raw...)

	baseline := Baseline{Roots: []RootEntry{rootEntry(certA), rootEntry(&certB)}}
	result := evaluateTrustStore(baseline, []*x509.Certificate{certA}, now)
	if result.MissingRoots != 1 {
		t.Fatalf("same-SPKI sibling removal was hidden: %+v", result)
	}
	var removedB bool
	for _, event := range result.Events {
		if event.Event == "EXPECTED_ROOT_REMOVED" && event.Subject == certB.Subject.String() {
			removedB = true
		}
	}
	if !removedB {
		t.Fatalf("missing exact certificate did not produce EXPECTED_ROOT_REMOVED: %#v", result.Events)
	}
}

func TestSameSPKICertificateChangeIsNotDeduplicatedAway(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	certA := &x509.Certificate{Subject: pkix.Name{CommonName: "Shared key"}, RawSubjectPublicKeyInfo: spki, Raw: []byte("certificate-a"), NotAfter: now.Add(time.Hour)}
	certB := &x509.Certificate{Subject: pkix.Name{CommonName: "Shared key"}, RawSubjectPublicKeyInfo: spki, Raw: []byte("certificate-b"), NotAfter: now.Add(time.Hour)}
	if got := deduplicateCertificates([]*x509.Certificate{certA, certB, certA}); len(got) != 2 {
		t.Fatalf("deduplicated distinct same-SPKI certificates: got %d, want 2", len(got))
	}
	result := evaluateTrustStore(Baseline{Roots: []RootEntry{rootEntry(certA)}}, []*x509.Certificate{certB}, now)
	if result.ChangedRoots != 1 || result.UnknownRoots != 0 || result.MissingRoots != 0 {
		t.Fatalf("same-SPKI certificate change was not classified as drift: %+v", result)
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
