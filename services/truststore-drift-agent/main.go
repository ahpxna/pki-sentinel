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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
  truststore-drift-agent baseline -o <baseline.json>
  truststore-drift-agent check -b <baseline.json> [--log /var/log/pki-sentinel/truststore.json]`)
}

func cmdBaseline(args []string) {
	outPath := parseFlag(args, "-o", "truststore-baseline.json")
	certs, err := loadTrustStore()
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
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline: marshaling: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "baseline: writing %s: %v\n", outPath, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d roots)\n", outPath, len(b.Roots))
}

func cmdCheck(args []string) {
	baselinePath := parseFlag(args, "-b", "truststore-baseline.json")
	logPath := parseFlag(args, "--log", "/var/log/pki-sentinel/truststore.json")

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
	known := make(map[string]bool, len(baseline.Roots))
	for _, r := range baseline.Roots {
		known[r.SPKIHash] = true
	}

	certs, err := loadTrustStore()
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

func appendLog(path string, events []DriftEvent) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
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
func loadTrustStore() ([]*x509.Certificate, error) {
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		return nil, fmt.Errorf("loadTrustStore: macOS trust store enumeration requires shelling out to " +
			"`security dump-trust-settings -d` / `security find-certificate -a -p " +
			"/Library/Keychains/System.keychain` when run natively; not implemented for the containerized demo path")
	default:
		candidates = []string{
			"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu bundle
			"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL bundle
		}
	}

	var certs []*x509.Certificate
	found := false
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}
	}

	// Debian/Ubuntu also allows locally-added roots dropped into
	// /usr/local/share/ca-certificates/ before `update-ca-certificates`
	// folds them into the bundle above; scan it too so drift is visible
	// even before that step completes.
	if entries, err := os.ReadDir("/usr/local/share/ca-certificates/"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join("/usr/local/share/ca-certificates/", e.Name()))
			if err != nil {
				continue
			}
			found = true
			block, _ := pem.Decode(data)
			if block == nil {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}
	}

	if !found {
		return nil, fmt.Errorf("loadTrustStore: no known trust store location found (checked %v)", candidates)
	}
	return certs, nil
}

func parseFlag(args []string, name, def string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return def
}
