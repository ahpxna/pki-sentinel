package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testScenarioDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var testRunConfig = json.RawMessage(`{"max_wait_ns":1,"enabled_profiles":[]}`)

func testRunConfigDigest() string {
	sum := sha256.Sum256(testRunConfig)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testPayload(cycleID string) []byte {
	return []byte(fmt.Sprintf(`{"cycle_id":%q,"scenario_digest":%q,"run_config":%s,"run_config_digest":%q}`, cycleID, testScenarioDigest, testRunConfig, testRunConfigDigest()))
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	envelope, err := SignJSON(privatePEM, testPayload("cycle-1"), time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Statement.RunID != "cycle-1" || envelope.Statement.ScenarioDigest != testScenarioDigest || envelope.Statement.RunConfigDigest != testRunConfigDigest() {
		t.Fatalf("statement did not bind payload identity: %#v", envelope.Statement)
	}
	if err := Verify(publicPEM, envelope); err != nil {
		t.Fatalf("verify signed envelope: %v", err)
	}
	envelope.Payload[0] ^= 1
	if err := Verify(publicPEM, envelope); err == nil {
		t.Fatal("verify accepted a modified payload")
	}
	envelope, err = SignJSON(privatePEM, testPayload("cycle-2"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	envelope.Statement.IssuedAt = envelope.Statement.IssuedAt.Add(time.Hour)
	if err := Verify(publicPEM, envelope); err == nil {
		t.Fatal("verify accepted modified signed metadata")
	}
}

func TestSignRejectsNonEd25519Key(t *testing.T) {
	t.Parallel()
	if _, err := SignJSON([]byte("not a key"), []byte(`{}`), time.Now()); err == nil {
		t.Fatal("Sign accepted an invalid key")
	}
}

func TestMarshalEnvelopeRoundTripPreservesSignedPayload(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	payload := []byte(fmt.Sprintf(`{"cycle_id":"cycle-roundtrip", "scenario_digest":%q, "run_config": %s, "run_config_digest":%q}`, testScenarioDigest, testRunConfig, testRunConfigDigest()))
	envelope, err := SignJSON(privatePEM, payload, time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if string(envelope.Payload) != string(payload) {
		t.Fatalf("signed payload changed bytes: got %q want %q", envelope.Payload, payload)
	}
	wire, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	wantFragment := append([]byte(`"payload":`), payload...)
	if !bytes.Contains(wire, wantFragment) {
		t.Fatalf("serialized envelope reformatted signed payload: %s", wire)
	}
	var decoded Envelope
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicPEM, decoded); err != nil {
		t.Fatalf("verify serialized envelope: %v", err)
	}
}

func TestSignJSONRejectsInvalidPayload(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if _, err := SignJSON(privatePEM, []byte(`{"broken":`), time.Now()); err == nil {
		t.Fatal("SignJSON accepted invalid JSON")
	}
	for _, payload := range []string{
		`{"scenario_digest":"` + testScenarioDigest + `","run_config":{},"run_config_digest":"` + testRunConfigDigest() + `"}`,
		`{"cycle_id":"cycle-missing-digest","run_config":{},"run_config_digest":"` + testRunConfigDigest() + `"}`,
		`{"cycle_id":"cycle-bad-digest","scenario_digest":"sha256:scenario","run_config":{},"run_config_digest":"` + testRunConfigDigest() + `"}`,
		`{"cycle_id":"cycle-missing-run-config","scenario_digest":"` + testScenarioDigest + `","run_config":{}}`,
		`{"cycle_id":"cycle-bad-run-config","scenario_digest":"` + testScenarioDigest + `","run_config":{},"run_config_digest":"sha256:config"}`,
	} {
		if _, err := SignJSON(privatePEM, []byte(payload), time.Now()); err == nil {
			t.Fatalf("SignJSON accepted payload without valid assurance identity: %s", payload)
		}
	}
}

func TestVerifyRejectsStatementPayloadIdentityMismatchEvenWhenResigned(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	envelope, err := SignJSON(privatePEM, testPayload("cycle-original"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	envelope.Statement.RunID = "cycle-other"
	statement, err := json.Marshal(envelope.Statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, statement))
	if err := Verify(publicPEM, envelope); err == nil || !strings.Contains(err.Error(), "run ID does not match") {
		t.Fatalf("Verify error=%v, want statement/payload identity mismatch", err)
	}
}

func TestReadEnvelopeRejectsUnknownAndDuplicateFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"unknown.json":   `{"statement":{"version":"pki-sentinel-assurance/v3","issued_at":"2026-08-25T00:00:00Z","run_id":"cycle","scenario_digest":"` + testScenarioDigest + `","run_config_digest":"` + testRunConfigDigest() + `","payload_sha256":"x","public_key_sha256":"y","unexpected":true},"payload":{"cycle_id":"cycle","scenario_digest":"` + testScenarioDigest + `","run_config":{},"run_config_digest":"` + testRunConfigDigest() + `"},"signature":"x"}`,
		"duplicate.json": `{"statement":{"version":"pki-sentinel-assurance/v3","issued_at":"2026-08-25T00:00:00Z","run_id":"cycle","run_id":"cycle2","scenario_digest":"` + testScenarioDigest + `","run_config_digest":"` + testRunConfigDigest() + `","payload_sha256":"x","public_key_sha256":"y"},"payload":{"cycle_id":"cycle","scenario_digest":"` + testScenarioDigest + `","run_config":{},"run_config_digest":"` + testRunConfigDigest() + `"},"signature":"x"}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadEnvelope(path); err == nil {
			t.Fatalf("ReadEnvelope accepted malformed %s", name)
		}
	}
}

func TestSignJSONRejectsDuplicatePayloadFields(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	payload := []byte(`{"cycle_id":"one","cycle_id":"two","scenario_digest":"` + testScenarioDigest + `","run_config":{},"run_config_digest":"` + testRunConfigDigest() + `"}`)
	if _, err := SignJSON(privatePEM, payload, time.Now()); err == nil {
		t.Fatal("SignJSON accepted duplicate payload fields")
	}
}

func TestVerifyRejectsRunConfigDigestMismatchEvenWhenSigned(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	payload := []byte(`{"cycle_id":"mismatch","scenario_digest":"` + testScenarioDigest + `","run_config":{"max_wait_ns":999},"run_config_digest":"` + testRunConfigDigest() + `"}`)
	if _, err := SignJSON(privatePEM, payload, time.Now()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("SignJSON error=%v, want run-config digest mismatch", err)
	}
	_ = publicPEM
}
