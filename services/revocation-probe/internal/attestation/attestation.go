// Package attestation signs durable assurance reports. The package deliberately
// signs the exact JSON bytes carried in the envelope, so a verifier does not
// need to reproduce Go's JSON serialization to validate a report.
package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

const Version = "pki-sentinel-assurance/v1"

// Envelope is a self-contained, detached-signature-friendly evidence record.
// Payload is retained as JSON so it can be archived and inspected without
// needing application-specific decoding before integrity verification.
type Envelope struct {
	Version         string          `json:"version"`
	IssuedAt        time.Time       `json:"issued_at"`
	Payload         json.RawMessage `json:"payload"`
	PayloadSHA256   string          `json:"payload_sha256"`
	PublicKeySHA256 string          `json:"public_key_sha256"`
	Signature       string          `json:"signature"`
}

// Sign serializes payload once and signs those exact bytes with an Ed25519
// PKCS#8 private key. The resulting envelope is suitable for append-only
// evidence storage or publication alongside the corresponding public key.
func Sign(privateKeyPEM []byte, payload any, now time.Time) (Envelope, error) {
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return Envelope{}, err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal attestation payload: %w", err)
	}
	payloadHash := sha256.Sum256(payloadJSON)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicKeyHash := sha256.Sum256(publicKey)

	return Envelope{
		Version:         Version,
		IssuedAt:        now.UTC(),
		Payload:         payloadJSON,
		PayloadSHA256:   hex.EncodeToString(payloadHash[:]),
		PublicKeySHA256: hex.EncodeToString(publicKeyHash[:]),
		Signature:       base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payloadJSON)),
	}, nil
}

// Verify confirms that an envelope was produced by publicKeyPEM and that its
// payload was not modified after signing.
func Verify(publicKeyPEM []byte, envelope Envelope) error {
	if envelope.Version != Version {
		return fmt.Errorf("unsupported attestation version %q", envelope.Version)
	}
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(envelope.Payload)
	if got := hex.EncodeToString(payloadHash[:]); got != envelope.PayloadSHA256 {
		return fmt.Errorf("payload SHA-256 mismatch")
	}
	publicKeyHash := sha256.Sum256(publicKey)
	if got := hex.EncodeToString(publicKeyHash[:]); got != envelope.PublicKeySHA256 {
		return fmt.Errorf("public key SHA-256 mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, envelope.Payload, signature) {
		return fmt.Errorf("invalid attestation signature")
	}
	return nil
}

// ReadPrivateKey reads an Ed25519 PKCS#8 private-key PEM file.
func ReadPrivateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read attestation private key: %w", err)
	}
	if _, err := parsePrivateKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ReadEnvelope reads an attestation envelope from JSON.
func ReadEnvelope(path string) (Envelope, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Envelope{}, fmt.Errorf("read attestation: %w", err)
	}
	var envelope Envelope
	if err := json.Unmarshal(contents, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("decode attestation: %w", err)
	}
	return envelope, nil
}

func parsePrivateKey(contents []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, fmt.Errorf("attestation private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse attestation private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("attestation private key must be Ed25519 PKCS#8")
	}
	return key, nil
}

func parsePublicKey(contents []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, fmt.Errorf("attestation public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse attestation public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("attestation public key must be Ed25519 PKIX")
	}
	return key, nil
}
