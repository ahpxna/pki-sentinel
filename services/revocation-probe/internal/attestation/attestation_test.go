package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

const testScenarioDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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

	envelope, err := SignJSON(privatePEM, []byte(`{"cycle_id":"cycle-1","scenario_digest":"`+testScenarioDigest+`"}`), time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Statement.RunID != "cycle-1" || envelope.Statement.ScenarioDigest != testScenarioDigest {
		t.Fatalf("statement did not bind payload identity: %#v", envelope.Statement)
	}
	if err := Verify(publicPEM, envelope); err != nil {
		t.Fatalf("verify signed envelope: %v", err)
	}
	envelope.Payload[0] ^= 1
	if err := Verify(publicPEM, envelope); err == nil {
		t.Fatal("verify accepted a modified payload")
	}
	envelope, err = SignJSON(privatePEM, []byte(`{"cycle_id":"cycle-2","scenario_digest":"`+testScenarioDigest+`"}`), time.Now())
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

	payload := []byte(`{"cycle_id":"cycle-roundtrip", "scenario_digest":"` + testScenarioDigest + `"}`)
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
		`{"scenario_digest":"` + testScenarioDigest + `"}`,
		`{"cycle_id":"cycle-missing-digest"}`,
		`{"cycle_id":"cycle-bad-digest","scenario_digest":"sha256:scenario"}`,
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
	envelope, err := SignJSON(privatePEM, []byte(`{"cycle_id":"cycle-original","scenario_digest":"`+testScenarioDigest+`"}`), time.Now())
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
