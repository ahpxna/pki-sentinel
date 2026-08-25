package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

type cyclePayload struct {
	CycleID        string `json:"cycle_id"`
	ScenarioDigest string `json:"scenario_digest"`
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

	envelope, err := Sign(privatePEM, cyclePayload{CycleID: "cycle-1", ScenarioDigest: "sha256:scenario"}, time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Statement.RunID != "cycle-1" || envelope.Statement.ScenarioDigest != "sha256:scenario" {
		t.Fatalf("statement did not bind payload identity: %#v", envelope.Statement)
	}
	if err := Verify(publicPEM, envelope); err != nil {
		t.Fatalf("verify signed envelope: %v", err)
	}
	envelope.Payload[0] ^= 1
	if err := Verify(publicPEM, envelope); err == nil {
		t.Fatal("verify accepted a modified payload")
	}
	envelope, err = Sign(privatePEM, map[string]string{"decision": "REJECT"}, time.Now())
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
	if _, err := Sign([]byte("not a key"), map[string]string{}, time.Now()); err == nil {
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

	envelope, err := Sign(privatePEM, cyclePayload{CycleID: "cycle-roundtrip", ScenarioDigest: "sha256:scenario"}, time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Envelope
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicPEM, decoded); err != nil {
		t.Fatalf("verify serialized envelope: %v", err)
	}
}
