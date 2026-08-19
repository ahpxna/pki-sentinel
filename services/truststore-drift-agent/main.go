// Command truststore-drift-agent enumerates the host trust store, computes
// SHA-256 over each root's SubjectPublicKeyInfo, and compares against a
// signed baseline to detect unauthorized root CA installation.
//
// This is the productized form of the trusted-CA MITM finding: a client
// with an attacker CA in its trust store accepts interception with zero
// warning and 100% success. That failure mode cannot be detected at the
// TLS layer — by design, the client trusts the connection — so detection
// has to happen at the trust-store layer instead. That is what this agent
// does.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

// RootEntry is one CA root's identity, as recorded in a baseline or
// observed on the live host.
type RootEntry struct {
	Subject  string `json:"subject"`
	SPKIHash string `json:"spki_sha256"`
}

// Baseline is the full signed set of trusted roots at a point in time.
type Baseline struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Roots       []RootEntry `json:"roots"`
	Signature   string      `json:"signature"`
}

// DriftEvent is emitted (stdout + log file) for each newly observed root
// not present in the baseline.
type DriftEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Subject   string    `json:"subject"`
	SPKIHash  string    `json:"spki_sha256"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "baseline":
		cmdBaseline(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  truststore-drift-agent baseline -o <baseline.json> [--private-key key.pem] [--public-key key.pub.pem] [--extra-ca-dir path]
  truststore-drift-agent check -b <baseline.json> [--public-key key.pub.pem] [--extra-ca-dir path] [--log /var/log/pki-sentinel/truststore.json]`)
}

func cmdBaseline(args []string) {
	outPath := parseFlag(args, "-o", "truststore-baseline.json")
	privateKeyPath := parseFlag(args, "--private-key", outPath+".key")
	publicKeyPath := parseFlag(args, "--public-key", outPath+".pub")
	extraCADir := parseFlag(args, "--extra-ca-dir", "/usr/local/share/ca-certificates")
	certs, err := loadTrustStore(extraCADir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline: %v\n", err)
		os.Exit(1)
	}
	b := Baseline{GeneratedAt: time.Now().UTC()}
	for _, c := range certs {
		b.Roots = append(b.Roots, RootEntry{
			Subject:  c.Subject.String(),
			SPKIHash: spkiHash(c),
		})
	}
	sort.Slice(b.Roots, func(i, j int) bool {
		if b.Roots[i].SPKIHash == b.Roots[j].SPKIHash {
			return b.Roots[i].Subject < b.Roots[j].Subject
		}
		return b.Roots[i].SPKIHash < b.Roots[j].SPKIHash
	})
	privateKey, err := loadOrCreateSigningKey(privateKeyPath, publicKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline: signing key: %v\n", err)
		os.Exit(1)
	}
	if err := signBaseline(&b, privateKey); err != nil {
		fmt.Fprintf(os.Stderr, "baseline: signing: %v\n", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline: marshaling: %v\n", err)
		os.Exit(1)
	}
	// #nosec G703 -- writing to an operator-supplied output path is the CLI's purpose.
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "baseline: writing %s: %v\n", outPath, err)
		os.Exit(1)
	}
	fmt.Printf("wrote signed baseline %s (%d roots); public key: %s\n", outPath, len(b.Roots), publicKeyPath)
}

func cmdCheck(args []string) {
	baselinePath := parseFlag(args, "-b", "truststore-baseline.json")
	publicKeyPath := parseFlag(args, "--public-key", baselinePath+".pub")
	extraCADir := parseFlag(args, "--extra-ca-dir", "/usr/local/share/ca-certificates")
	logPath := parseFlag(args, "--log", "/var/log/pki-sentinel/truststore.json")

	// #nosec G703 -- reading an operator-selected baseline path is intentional.
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check: reading baseline: %v\n", err)
		os.Exit(1)
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		fmt.Fprintf(os.Stderr, "check: parsing baseline: %v\n", err)
		os.Exit(1)
	}
	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check: loading public key: %v\n", err)
		os.Exit(1)
	}
	if err := verifyBaseline(baseline, publicKey); err != nil {
		fmt.Fprintf(os.Stderr, "check: baseline signature verification failed: %v\n", err)
		os.Exit(1)
	}
	known := make(map[string]bool, len(baseline.Roots))
	for _, r := range baseline.Roots {
		known[r.SPKIHash] = true
	}

	certs, err := loadTrustStore(extraCADir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check: %v\n", err)
		os.Exit(1)
	}

	unknownCount := 0
	var events []DriftEvent
	for _, c := range certs {
		hash := spkiHash(c)
		if known[hash] {
			continue
		}
		unknownCount++
		ev := DriftEvent{
			Timestamp: time.Now().UTC(),
			Event:     "unknown_root",
			Subject:   c.Subject.String(),
			SPKIHash:  hash,
		}
		events = append(events, ev)
		line, _ := json.Marshal(ev)
		fmt.Println(string(line))
	}

	fmt.Printf("pki_truststore_unknown_roots %d\n", unknownCount)

	if len(events) > 0 {
		if err := appendLog(logPath, events); err != nil {
			fmt.Fprintf(os.Stderr, "check: WARNING: could not write %s: %v\n", logPath, err)
		}
	}

	if unknownCount > 0 {
		os.Exit(1)
	}
}

func baselinePayload(b Baseline) ([]byte, error) {
	b.Signature = ""
	return json.Marshal(b)
}

func signBaseline(b *Baseline, privateKey ed25519.PrivateKey) error {
	payload, err := baselinePayload(*b)
	if err != nil {
		return err
	}
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func verifyBaseline(b Baseline, publicKey ed25519.PublicKey) error {
	signature, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	payload, err := baselinePayload(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func loadOrCreateSigningKey(privatePath, publicPath string) (ed25519.PrivateKey, error) {
	// #nosec G703 -- the signing-key path is explicitly selected by the operator.
	if data, err := os.ReadFile(privatePath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decoding private key PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519")
		}
		publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
		if err != nil {
			return nil, err
		}
		// #nosec G703 -- key destination is an explicit operator-supplied CLI path.
		if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
			return nil, err
		}
		return privateKey, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	// #nosec G703 -- key destinations are explicit operator-supplied CLI paths.
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		return nil, err
	}
	// #nosec G703 -- key destinations are explicit operator-supplied CLI paths.
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	// #nosec G703 -- public-key path is explicitly selected by the operator.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decoding public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}
	return publicKey, nil
}

func appendLog(path string, events []DriftEvent) error {
	// #nosec G703 -- the log destination is an explicit operator-supplied CLI path.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// #nosec G703 -- the log destination is an explicit operator-supplied CLI path.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

func spkiHash(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// loadTrustStore enumerates trusted root CAs from the platform-appropriate
// location(s):
//   - Debian/Ubuntu: /etc/ssl/certs/ca-certificates.crt,
//     /usr/local/share/ca-certificates/
//   - RHEL: /etc/pki/ca-trust/
//   - macOS (native only): `security dump-trust-settings -d` /
//     `security find-certificate -a -p /Library/Keychains/System.keychain`
func loadTrustStore(extraCADir string) ([]*x509.Certificate, error) {
	var candidates []string
	var certs []*x509.Certificate
	found := false
	switch runtime.GOOS {
	case "darwin":
		// With no explicit keychain, security searches the user's configured
		// keychain list. Include Apple's immutable system roots explicitly as
		// they are not guaranteed to be in that list in non-interactive jobs.
		commands := [][]string{
			{"find-certificate", "-a", "-p"},
			{"find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"},
			{"find-certificate", "-a", "-p", "/Library/Keychains/System.keychain"},
		}
		for _, args := range commands {
			data, err := exec.Command("security", args...).Output()
			if err != nil {
				continue
			}
			found = true
			certs = appendPEMCertificates(certs, data)
		}
	default:
		candidates = []string{
			"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu bundle
			"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL bundle
		}
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		certs = appendPEMCertificates(certs, data)
	}

	// Debian/Ubuntu also allows locally-added roots dropped into
	// /usr/local/share/ca-certificates/ before `update-ca-certificates`
	// folds them into the bundle above; scan it too so drift is visible
	// even before that step completes.
	dirs := []string{extraCADir}
	if runtime.GOOS != "darwin" {
		dirs = append(dirs, "/etc/pki/ca-trust/source/anchors", "/etc/pki/ca-trust/extracted/pem")
	}
	for _, dir := range dirs {
		root, err := os.OpenRoot(dir)
		if err != nil {
			continue
		}
		_ = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			data, err := root.ReadFile(path)
			if err != nil {
				return nil
			}
			found = true
			certs = appendPEMCertificates(certs, data)
			return nil
		})
		_ = root.Close()
	}

	if !found {
		return nil, fmt.Errorf("loadTrustStore: no known trust store location found (checked %v)", candidates)
	}
	unique := make([]*x509.Certificate, 0, len(certs))
	seen := make(map[string]struct{}, len(certs))
	for _, cert := range certs {
		hash := spkiHash(cert)
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		unique = append(unique, cert)
	}
	return unique, nil
}

func appendPEMCertificates(certs []*x509.Certificate, data []byte) []*x509.Certificate {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

func parseFlag(args []string, name, def string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return def
}
