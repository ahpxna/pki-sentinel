// Package attestation signs durable assurance reports. The signed statement
// binds report metadata to the SHA-256 digest of the exact JSON payload, so a
// verifier can validate both without reproducing JSON serialization.
package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

const Version = "pki-sentinel-assurance/v3"

// Statement is the complete signed to-be-signed record. The payload itself is
// content-addressed, so changing any envelope metadata that gives the report
// meaning (including issued_at) invalidates the signature.
type Statement struct {
	Version         string    `json:"version"`
	IssuedAt        time.Time `json:"issued_at"`
	RunID           string    `json:"run_id"`
	ScenarioDigest  string    `json:"scenario_digest"`
	RunConfigDigest string    `json:"run_config_digest"`
	PayloadSHA256   string    `json:"payload_sha256"`
	PublicKeySHA256 string    `json:"public_key_sha256"`
}

// Envelope is a self-contained, detached-signature-friendly evidence record.
// Payload is retained as JSON so it can be archived and inspected without
// needing application-specific decoding before integrity verification.
type Envelope struct {
	Statement Statement       `json:"statement"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// MarshalEnvelope serializes the outer envelope while preserving Payload
// byte-for-byte. encoding/json compacts json.RawMessage values during Marshal,
// so marshaling Envelope directly would make payload integrity depend on the
// payload already being compact. Building the three-field envelope around the
// validated raw payload keeps the signed representation exact by construction.
func MarshalEnvelope(envelope Envelope) ([]byte, error) {
	if !json.Valid(envelope.Payload) {
		return nil, fmt.Errorf("attestation payload is not valid JSON")
	}
	statement, err := json.Marshal(envelope.Statement)
	if err != nil {
		return nil, fmt.Errorf("encode attestation statement: %w", err)
	}
	signature, err := json.Marshal(envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("encode attestation signature: %w", err)
	}

	contents := make([]byte, 0, len(statement)+len(envelope.Payload)+len(signature)+40)
	contents = append(contents, `{"statement":`...)
	contents = append(contents, statement...)
	contents = append(contents, `,"payload":`...)
	contents = append(contents, envelope.Payload...)
	contents = append(contents, `,"signature":`...)
	contents = append(contents, signature...)
	contents = append(contents, '}')
	return contents, nil
}

// SignJSON signs an already-serialized JSON payload without re-encoding it.
// The caller owns payload canonicalization; this function validates and copies
// the exact bytes before hashing them so stdout, archived evidence, and the
// signed payload can share one representation.
func SignJSON(privateKeyPEM []byte, payloadJSON []byte, now time.Time) (Envelope, error) {
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return Envelope{}, err
	}
	if !json.Valid(payloadJSON) {
		return Envelope{}, fmt.Errorf("attestation payload is not valid JSON")
	}
	if err := rejectDuplicateJSONKeys(payloadJSON); err != nil {
		return Envelope{}, fmt.Errorf("attestation payload: %w", err)
	}
	payload := append(json.RawMessage(nil), payloadJSON...)
	runID, scenarioDigest, configDigest, err := payloadIdentity(payload)
	if err != nil {
		return Envelope{}, err
	}
	payloadHash := sha256.Sum256(payload)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicKeyHash := sha256.Sum256(publicKey)

	statement := Statement{
		Version:         Version,
		IssuedAt:        now.UTC(),
		RunID:           runID,
		ScenarioDigest:  scenarioDigest,
		RunConfigDigest: configDigest,
		PayloadSHA256:   hex.EncodeToString(payloadHash[:]),
		PublicKeySHA256: hex.EncodeToString(publicKeyHash[:]),
	}
	toBeSigned, err := json.Marshal(statement)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal attestation statement: %w", err)
	}
	return Envelope{
		Statement: statement,
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, toBeSigned)),
	}, nil
}

// Verify confirms that an envelope was produced by publicKeyPEM and that its
// payload was not modified after signing.
func Verify(publicKeyPEM []byte, envelope Envelope) error {
	if envelope.Statement.Version != Version {
		return fmt.Errorf("unsupported attestation version %q", envelope.Statement.Version)
	}
	if !json.Valid(envelope.Payload) {
		return fmt.Errorf("attestation payload is not valid JSON")
	}
	if err := rejectDuplicateJSONKeys(envelope.Payload); err != nil {
		return fmt.Errorf("attestation payload: %w", err)
	}
	runID, scenarioDigest, configDigest, err := payloadIdentity(envelope.Payload)
	if err != nil {
		return err
	}
	if envelope.Statement.RunID != runID {
		return fmt.Errorf("attestation run ID does not match payload cycle_id")
	}
	if envelope.Statement.ScenarioDigest != scenarioDigest {
		return fmt.Errorf("attestation scenario digest does not match payload scenario_digest")
	}
	if envelope.Statement.RunConfigDigest != configDigest {
		return fmt.Errorf("attestation run config digest does not match payload run_config_digest")
	}
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(envelope.Payload)
	if got := hex.EncodeToString(payloadHash[:]); got != envelope.Statement.PayloadSHA256 {
		return fmt.Errorf("payload SHA-256 mismatch")
	}
	publicKeyHash := sha256.Sum256(publicKey)
	if got := hex.EncodeToString(publicKeyHash[:]); got != envelope.Statement.PublicKeySHA256 {
		return fmt.Errorf("public key SHA-256 mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	toBeSigned, err := json.Marshal(envelope.Statement)
	if err != nil {
		return fmt.Errorf("marshal attestation statement: %w", err)
	}
	if !ed25519.Verify(publicKey, toBeSigned, signature) {
		return fmt.Errorf("invalid attestation signature")
	}
	return nil
}

func payloadIdentity(payload json.RawMessage) (string, string, string, error) {
	var identity struct {
		CycleID         string `json:"cycle_id"`
		ScenarioDigest  string `json:"scenario_digest"`
		RunConfigDigest string `json:"run_config_digest"`
	}
	if err := json.Unmarshal(payload, &identity); err != nil {
		return "", "", "", fmt.Errorf("decode attestation payload identity: %w", err)
	}
	if identity.CycleID == "" {
		return "", "", "", fmt.Errorf("attestation payload cycle_id is required")
	}
	if !validDigest(identity.ScenarioDigest) {
		return "", "", "", fmt.Errorf("attestation payload scenario_digest %q is not a canonical SHA-256 digest", identity.ScenarioDigest)
	}
	if !validDigest(identity.RunConfigDigest) {
		return "", "", "", fmt.Errorf("attestation payload run_config_digest %q is not a canonical SHA-256 digest", identity.RunConfigDigest)
	}
	return identity.CycleID, identity.ScenarioDigest, identity.RunConfigDigest, nil
}

func validDigest(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+sha256.Size*2 || value[:len(prefix)] != prefix {
		return false
	}
	decoded, err := hex.DecodeString(value[len(prefix):])
	return err == nil && len(decoded) == sha256.Size
}

func rejectDuplicateJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := scanJSONValue(decoder, "$", nil); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, path string, first json.Token) error {
	token := first
	var err error
	if token == nil {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s: object key is not a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s: duplicate JSON field %q", path, key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, path+"."+key, nil); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		index := 0
		for decoder.More() {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), nil); err != nil {
				return err
			}
			index++
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("%s: unexpected JSON delimiter %q", path, delim)
	}
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
	if err := rejectDuplicateJSONKeys(contents); err != nil {
		return Envelope{}, fmt.Errorf("decode attestation: %w", err)
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, fmt.Errorf("decode attestation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Envelope{}, fmt.Errorf("decode attestation: multiple JSON values are not allowed")
		}
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
