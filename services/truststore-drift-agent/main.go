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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// RootEntry is one CA root's identity, as recorded in a baseline or
// observed on the live host.
type RootEntry struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	SPKIHash           string    `json:"spki_sha256"`
	CertHash           string    `json:"cert_sha256"`
	PolicyHash         string    `json:"policy_sha256"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsCA               bool      `json:"is_ca"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
}

// Baseline is the full signed set of trusted roots at a point in time.
type Baseline struct {
	GeneratedAt    time.Time   `json:"generated_at"`
	Sequence       uint64      `json:"sequence"`
	ExpiresAt      time.Time   `json:"expires_at"`
	PreviousDigest string      `json:"previous_policy_digest,omitempty"`
	Roots          []RootEntry `json:"roots"`
	Signature      string      `json:"signature"`
}

// BaselineState is local monotonic state used to reject a validly signed but
// older baseline replay. It must live on durable storage separate from the
// baseline artifact distribution channel.
type BaselineState struct {
	HighestSequence uint64 `json:"highest_sequence"`
	Digest          string `json:"digest"`
}

// DriftEvent is emitted (stdout + log file) for each newly observed root
// not present in the baseline.
type DriftEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Subject   string    `json:"subject"`
	SPKIHash  string    `json:"spki_sha256"`
}

// ScanResult is the bounded state exported to Prometheus. Detailed root
// identities remain in the event stream rather than metric labels.
type ScanResult struct {
	UnknownRoots  int          `json:"unknown_roots"`
	MissingRoots  int          `json:"missing_roots"`
	ChangedRoots  int          `json:"changed_roots"`
	ExpiredRoots  int          `json:"expired_roots"`
	ExpiringRoots int          `json:"expiring_roots"`
	BaselineValid bool         `json:"baseline_valid"`
	ScanSuccess   bool         `json:"scan_success"`
	LastScan      time.Time    `json:"last_scan"`
	Events        []DriftEvent `json:"events,omitempty"`
	Error         string       `json:"error,omitempty"`
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
	case "serve":
		cmdServe(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  truststore-drift-agent baseline -o <baseline.json> [--sequence N] [--previous-digest SHA256] [--expires-in 8760h] [--private-key key.pem] [--public-key key.pub.pem] [--extra-ca-dir path]
  truststore-drift-agent check -b <baseline.json> [--public-key key.pub.pem] [--state baseline.state] [--extra-ca-dir path] [--log /var/log/pki-sentinel/truststore.json]
  truststore-drift-agent serve -b <baseline.json> [--public-key key.pub.pem] [--state baseline.state] [--extra-ca-dir path] [--listen :9120] [--interval 60s]`)
}

func cmdBaseline(args []string) {
	outPath := parseFlag(args, "-o", "truststore-baseline.json")
	privateKeyPath := parseFlag(args, "--private-key", outPath+".key")
	publicKeyPath := parseFlag(args, "--public-key", outPath+".pub")
	extraCADir := parseFlag(args, "--extra-ca-dir", "/usr/local/share/ca-certificates")
	sequenceText := parseFlag(args, "--sequence", "1")
	previousDigest := parseFlag(args, "--previous-digest", "")
	expiresInText := parseFlag(args, "--expires-in", "8760h")
	var sequence uint64
	if _, err := fmt.Sscan(sequenceText, &sequence); err != nil || sequence == 0 {
		fmt.Fprintf(os.Stderr, "baseline: invalid --sequence %q\n", sequenceText)
		os.Exit(2)
	}
	if sequence > 1 && previousDigest == "" {
		fmt.Fprintln(os.Stderr, "baseline: --previous-digest is required when --sequence is greater than 1")
		os.Exit(2)
	}
	expiresIn, err := time.ParseDuration(expiresInText)
	if err != nil || expiresIn <= 0 {
		fmt.Fprintf(os.Stderr, "baseline: invalid --expires-in %q\n", expiresInText)
		os.Exit(2)
	}
	certs, err := loadTrustStore(extraCADir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline: %v\n", err)
		os.Exit(1)
	}
	now := time.Now().UTC()
	b := Baseline{GeneratedAt: now, Sequence: sequence, PreviousDigest: previousDigest, ExpiresAt: now.Add(expiresIn)}
	for _, c := range certs {
		b.Roots = append(b.Roots, rootEntry(c))
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
	digest, err := baselineDigest(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline: hashing: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote signed baseline %s (%d roots); sequence=%d digest=%s; public key: %s\n", outPath, len(b.Roots), b.Sequence, digest, publicKeyPath)
}

func cmdCheck(args []string) {
	baselinePath := parseFlag(args, "-b", "truststore-baseline.json")
	publicKeyPath := parseFlag(args, "--public-key", baselinePath+".pub")
	statePath := parseFlag(args, "--state", baselinePath+".state")
	extraCADir := parseFlag(args, "--extra-ca-dir", "/usr/local/share/ca-certificates")
	logPath := parseFlag(args, "--log", "/var/log/pki-sentinel/truststore.json")
	result := scanTrustStore(baselinePath, publicKeyPath, statePath, extraCADir, time.Now().UTC())
	for _, event := range result.Events {
		line, _ := json.Marshal(event)
		fmt.Println(string(line))
	}
	fmt.Print(prometheusText(result))
	if logPath != "" && len(result.Events) > 0 {
		if err := appendLog(logPath, result.Events); err != nil {
			fmt.Fprintf(os.Stderr, "check: WARNING: could not write %s: %v\n", logPath, err)
		}
	}
	if !result.BaselineValid || !result.ScanSuccess {
		fmt.Fprintf(os.Stderr, "check: %s\n", result.Error)
		os.Exit(2)
	}
	if result.UnknownRoots > 0 || result.MissingRoots > 0 || result.ExpiredRoots > 0 {
		os.Exit(1)
	}
}

func loadVerifiedBaseline(baselinePath, publicKeyPath, statePath string) (Baseline, error) {
	// #nosec G703 -- reading an operator-selected baseline path is intentional.
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		return Baseline{}, fmt.Errorf("reading baseline: %w", err)
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return Baseline{}, fmt.Errorf("parsing baseline: %w", err)
	}
	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		return Baseline{}, fmt.Errorf("loading public key: %w", err)
	}
	if err := verifyBaseline(baseline, publicKey); err != nil {
		return Baseline{}, fmt.Errorf("baseline signature verification failed: %w", err)
	}
	if baseline.Sequence == 0 || baseline.ExpiresAt.IsZero() {
		return Baseline{}, fmt.Errorf("baseline lacks required sequence or expiry")
	}
	if time.Now().UTC().After(baseline.ExpiresAt) {
		return Baseline{}, fmt.Errorf("baseline expired at %s", baseline.ExpiresAt.Format(time.RFC3339))
	}
	if err := verifyAndAdvanceBaselineState(baseline, statePath); err != nil {
		return Baseline{}, err
	}
	return baseline, nil
}

func scanTrustStore(baselinePath, publicKeyPath, statePath, extraCADir string, now time.Time) ScanResult {
	result := ScanResult{LastScan: now}
	baseline, err := loadVerifiedBaseline(baselinePath, publicKeyPath, statePath)
	if err != nil {
		result.Error = err.Error()
		result.Events = []DriftEvent{{Timestamp: now, Event: "BASELINE_INVALID"}}
		return result
	}
	result.BaselineValid = true
	certs, err := loadTrustStore(extraCADir)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	return evaluateTrustStore(baseline, certs, now)
}

func evaluateTrustStore(baseline Baseline, certs []*x509.Certificate, now time.Time) ScanResult {
	result := ScanResult{BaselineValid: true, ScanSuccess: true, LastScan: now}
	knownByHash := make(map[string]RootEntry, len(baseline.Roots))
	knownBySubject := make(map[string]RootEntry, len(baseline.Roots))
	observedByHash := make(map[string]*x509.Certificate, len(certs))
	for _, root := range baseline.Roots {
		knownByHash[root.SPKIHash] = root
		knownBySubject[root.Subject] = root
	}
	for _, cert := range certs {
		observedByHash[spkiHash(cert)] = cert
	}

	for _, c := range certs {
		hash := spkiHash(c)
		subject := c.Subject.String()
		if known, exists := knownByHash[hash]; !exists {
			result.UnknownRoots++
			eventType := "UNKNOWN_ROOT_ADDED"
			if _, sameSubject := knownBySubject[subject]; sameSubject {
				result.ChangedRoots++
				eventType = "ROOT_CHANGED"
			}
			result.Events = append(result.Events, DriftEvent{
				Timestamp: now, Event: eventType, Subject: subject, SPKIHash: hash,
			})
		} else {
			observed := rootEntry(c)
			if known.CertHash != "" && known.CertHash != observed.CertHash {
				result.ChangedRoots++
				eventType := "ROOT_CERT_CHANGED"
				if known.PolicyHash != observed.PolicyHash {
					eventType = "ROOT_POLICY_CHANGED"
				}
				result.Events = append(result.Events, DriftEvent{Timestamp: now, Event: eventType, Subject: subject, SPKIHash: hash})
			}
		}
		if now.After(c.NotAfter) {
			result.ExpiredRoots++
			result.Events = append(result.Events, DriftEvent{
				Timestamp: now, Event: "ROOT_EXPIRED", Subject: subject, SPKIHash: hash,
			})
		} else if c.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
			result.ExpiringRoots++
			result.Events = append(result.Events, DriftEvent{
				Timestamp: now, Event: "ROOT_EXPIRING", Subject: subject, SPKIHash: hash,
			})
		}
	}
	for hash, root := range knownByHash {
		if _, observed := observedByHash[hash]; observed {
			continue
		}
		result.MissingRoots++
		result.Events = append(result.Events, DriftEvent{
			Timestamp: now, Event: "EXPECTED_ROOT_REMOVED", Subject: root.Subject, SPKIHash: root.SPKIHash,
		})
	}
	return result
}

func prometheusText(result ScanResult) string {
	boolFloat := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	return fmt.Sprintf(`# HELP pki_truststore_unknown_roots Roots present but absent from the signed baseline.
# TYPE pki_truststore_unknown_roots gauge
pki_truststore_unknown_roots %d
# HELP pki_truststore_missing_roots Baseline roots absent from the observed trust store.
# TYPE pki_truststore_missing_roots gauge
pki_truststore_missing_roots %d
# HELP pki_truststore_changed_roots Observed roots whose subject matches a baseline root but whose SPKI differs.
# TYPE pki_truststore_changed_roots gauge
pki_truststore_changed_roots %d
# HELP pki_truststore_expired_roots Expired roots in the observed trust store.
# TYPE pki_truststore_expired_roots gauge
pki_truststore_expired_roots %d
# HELP pki_truststore_expiring_roots Roots expiring within 30 days.
# TYPE pki_truststore_expiring_roots gauge
pki_truststore_expiring_roots %d
# HELP pki_truststore_baseline_valid Whether the baseline signature verified.
# TYPE pki_truststore_baseline_valid gauge
pki_truststore_baseline_valid %d
# HELP pki_truststore_scan_success Whether the trust store was scanned successfully.
# TYPE pki_truststore_scan_success gauge
pki_truststore_scan_success %d
# HELP pki_truststore_last_scan_timestamp_seconds Unix timestamp of the last scan attempt.
# TYPE pki_truststore_last_scan_timestamp_seconds gauge
pki_truststore_last_scan_timestamp_seconds %d
`, result.UnknownRoots, result.MissingRoots, result.ChangedRoots, result.ExpiredRoots,
		result.ExpiringRoots, boolFloat(result.BaselineValid), boolFloat(result.ScanSuccess), result.LastScan.Unix())
}

func cmdServe(args []string) {
	baselinePath := parseFlag(args, "-b", "truststore-baseline.json")
	publicKeyPath := parseFlag(args, "--public-key", baselinePath+".pub")
	statePath := parseFlag(args, "--state", baselinePath+".state")
	extraCADir := parseFlag(args, "--extra-ca-dir", "/usr/local/share/ca-certificates")
	logPath := parseFlag(args, "--log", "/var/log/pki-sentinel/truststore.json")
	listenAddr := parseFlag(args, "--listen", ":9120")
	intervalText := parseFlag(args, "--interval", "60s")
	interval, err := time.ParseDuration(intervalText)
	if err != nil || interval <= 0 {
		fmt.Fprintf(os.Stderr, "serve: invalid --interval %q\n", intervalText)
		os.Exit(2)
	}

	var mu sync.RWMutex
	current := ScanResult{LastScan: time.Now().UTC(), Error: "initial scan has not completed"}
	scan := func() {
		result := scanTrustStore(baselinePath, publicKeyPath, statePath, extraCADir, time.Now().UTC())
		if logPath != "" && len(result.Events) > 0 {
			if err := appendLog(logPath, result.Events); err != nil {
				fmt.Fprintf(os.Stderr, "serve: writing events: %v\n", err)
			}
		}
		mu.Lock()
		current = result
		mu.Unlock()
	}
	scan()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			scan()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		result := current
		mu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(prometheusText(result)))
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		result := current
		mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		ready := current.BaselineValid && current.ScanSuccess
		mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	fmt.Printf("truststore-drift-agent serving on %s every %s\n", listenAddr, interval)
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
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

func baselineDigest(b Baseline) (string, error) {
	payload, err := baselinePayload(b)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func verifyAndAdvanceBaselineState(baseline Baseline, statePath string) error {
	if statePath == "" {
		return fmt.Errorf("baseline state path is required for rollback protection")
	}
	digest, err := baselineDigest(baseline)
	if err != nil {
		return fmt.Errorf("hash baseline: %w", err)
	}
	root, stateName, err := openBaselineStateRoot(statePath)
	if err != nil {
		return err
	}
	defer root.Close()

	state := BaselineState{}
	if data, err := root.ReadFile(stateName); err == nil {
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("parse baseline state: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read baseline state: %w", err)
	}
	if baseline.Sequence < state.HighestSequence {
		return fmt.Errorf("baseline rollback: sequence %d is lower than highest seen %d", baseline.Sequence, state.HighestSequence)
	}
	if baseline.Sequence == state.HighestSequence && state.Digest != "" && state.Digest != digest {
		return fmt.Errorf("baseline equivocation: sequence %d has a different digest", baseline.Sequence)
	}
	if baseline.Sequence > state.HighestSequence && state.Digest != "" && baseline.PreviousDigest != state.Digest {
		return fmt.Errorf("baseline chain mismatch: sequence %d does not reference the accepted prior digest", baseline.Sequence)
	}
	if baseline.Sequence == state.HighestSequence && state.Digest == digest {
		return nil
	}
	data, err := json.Marshal(BaselineState{HighestSequence: baseline.Sequence, Digest: digest})
	if err != nil {
		return fmt.Errorf("encode baseline state: %w", err)
	}
	if err := writeBaselineStateAtomic(root, stateName, data); err != nil {
		return fmt.Errorf("write baseline state: %w", err)
	}
	return nil
}

// openBaselineStateRoot anchors all state-file operations to the selected
// parent directory. os.Root rejects symlink/path traversal that would escape
// that directory, so an attacker cannot redirect rollback state writes to an
// arbitrary host path through the state filename.
func openBaselineStateRoot(statePath string) (*os.Root, string, error) {
	cleaned := filepath.Clean(statePath)
	stateName := filepath.Base(cleaned)
	if stateName == "." || stateName == ".." || stateName == string(filepath.Separator) {
		return nil, "", fmt.Errorf("invalid baseline state path %q", statePath)
	}
	stateDir := filepath.Dir(cleaned)
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, "", fmt.Errorf("open baseline state directory %s: %w (create the directory before running the agent)", stateDir, err)
	}
	return root, stateName, nil
}

// writeBaselineStateAtomic persists monotonic rollback state without exposing
// a truncated/partially-written file after a crash. The temporary file lives
// in the same rooted directory, is fsync'd, atomically renamed, and then the
// directory entry is fsync'd as well.
func writeBaselineStateAtomic(root *os.Root, stateName string, data []byte) error {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("generate temporary state name: %w", err)
	}
	tempName := fmt.Sprintf(".%s.tmp-%x", stateName, suffix)
	file, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = root.Remove(tempName)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary state: %w", err)
	}
	if err := root.Rename(tempName, stateName); err != nil {
		return fmt.Errorf("replace baseline state: %w", err)
	}
	cleanup = false
	if dir, err := root.Open("."); err == nil {
		if syncErr := dir.Sync(); syncErr != nil {
			_ = dir.Close()
			return fmt.Errorf("sync baseline state directory: %w", syncErr)
		}
		if err := dir.Close(); err != nil {
			return fmt.Errorf("close baseline state directory: %w", err)
		}
	} else {
		return fmt.Errorf("open baseline state directory for sync: %w", err)
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

func certificateHash(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func rootEntry(c *x509.Certificate) RootEntry {
	policy, _ := json.Marshal(struct {
		IsCA                bool
		KeyUsage            x509.KeyUsage
		ExtKeyUsage         []x509.ExtKeyUsage
		PermittedDNSDomains []string
		PolicyIdentifiers   any
	}{c.IsCA, c.KeyUsage, c.ExtKeyUsage, c.PermittedDNSDomains, c.PolicyIdentifiers})
	policyDigest := sha256.Sum256(policy)
	return RootEntry{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: c.SerialNumber.String(), SPKIHash: spkiHash(c), CertHash: certificateHash(c), PolicyHash: hex.EncodeToString(policyDigest[:]),
		NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), IsCA: c.IsCA, KeyUsage: keyUsageNames(c.KeyUsage), SignatureAlgorithm: c.SignatureAlgorithm.String(),
	}
}

func keyUsageNames(usage x509.KeyUsage) []string {
	values := []struct {
		bit  x509.KeyUsage
		name string
	}{{x509.KeyUsageDigitalSignature, "digital_signature"}, {x509.KeyUsageCertSign, "cert_sign"}, {x509.KeyUsageCRLSign, "crl_sign"}}
	var names []string
	for _, value := range values {
		if usage&value.bit != 0 {
			names = append(names, value.name)
		}
	}
	return names
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
