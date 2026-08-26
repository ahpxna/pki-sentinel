// Command probe is the revocation-probe CLI: `run` executes cycles on a
// schedule (or once, with --once), `check` runs a single profile standalone
// against an arbitrary target, and `chaos` sweeps responder-scoped latency
// while recording direct-OCSP oracle failure rates.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/attestation"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/chaos"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/config"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/executor"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/issuer"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/metrics"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/runner"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/scenarios"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "chaos":
		cmdChaos(os.Args[2:])
	case "attest":
		cmdAttest(os.Args[2:])
	case "executor":
		cmdExecutor(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
	probe run   [--once] [--config profiles.yaml] [--scenario <id>] [--output json]
  probe check --profile <name> --target <https://host:port> --ca <chain.pem> [--leaf-sha256 HEX] [--ocsp-url URL] [--crl-url URL]
  probe chaos sweep [--delays 0,1000,2000] [--trials 5] [--out path.csv]
  probe attest verify --public-key attestation.pub --input cycle.attestation.json
  probe executor --profile <name> [--listen :8120]`)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// --- run ---------------------------------------------------------------

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	once := fs.Bool("once", false, "run a single cycle and exit")
	cfgPath := fs.String("config", "profiles.yaml", "path to profiles.yaml")
	scenarioDir := fs.String("scenarios", "scenarios", "directory containing scenario manifests")
	scenarioID := fs.String("scenario", "revoked_staple", "scenario manifest ID to execute")
	output := fs.String("output", "text", "output format: text|json")
	interval := fs.Duration("interval", 15*time.Minute, "cycle interval when not --once")
	metricsAddr := fs.String("metrics-addr", ":9110", "address to serve /metrics, /healthz, /readyz")
	attestationKey := fs.String("attestation-key", env("ASSURANCE_ATTESTATION_KEY", ""), "Ed25519 PKCS#8 private-key PEM used to sign each cycle report")
	attestationOut := fs.String("attestation-out", env("ASSURANCE_ATTESTATION_OUT", ""), "attestation envelope JSON path (requires --attestation-key)")
	_ = fs.Parse(args)
	if *output != "text" && *output != "json" {
		log.Fatalf("probe run: invalid --output %q; expected text or json", *output)
	}
	if *interval <= 0 {
		log.Fatal("probe run: --interval must be positive")
	}
	if (*attestationKey == "") != (*attestationOut == "") {
		log.Fatal("probe run: --attestation-key and --attestation-out must be supplied together")
	}
	var attestationPrivateKey []byte
	if *attestationKey != "" {
		var err error
		attestationPrivateKey, err = attestation.ReadPrivateKey(*attestationKey)
		if err != nil {
			log.Fatalf("probe run: %v", err)
		}
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("probe run: %v", err)
	}
	registry := profiles.Registry()
	knownProfiles := make([]string, 0, len(registry))
	for _, profile := range registry {
		knownProfiles = append(knownProfiles, profile.Name)
	}
	if err := cfg.ValidateEnabledProfiles(knownProfiles); err != nil {
		log.Fatalf("probe run: %v", err)
	}
	scenarioRegistry, err := scenarios.LoadDir(*scenarioDir, registry)
	if err != nil {
		log.Fatalf("probe run: loading scenarios: %v", err)
	}
	if err := scenarioRegistry.ValidateEnabledProfiles(cfg.EnabledNames()); err != nil {
		log.Fatalf("probe run: validating scenarios: %v", err)
	}
	selectedScenario, ok := scenarioRegistry.Manifest(profiles.Scenario(*scenarioID))
	if !ok {
		log.Fatalf("probe run: selected scenario %q is not loaded", *scenarioID)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if !*once {
		go func() {
			if err := metrics.Serve(ctx, *metricsAddr); err != nil {
				log.Printf("probe run: metrics server error: %v", err)
			}
		}()
	}

	vaultAddr := env("VAULT_ADDR", "http://vault:8200")
	roleID := env("VAULT_ROLE_ID", "")
	secretID := env("VAULT_SECRET_ID", "")
	vaultPublicAddr := env("VAULT_PUBLIC_ADDR", "http://localhost:8200")
	domain := env("PKI_DOMAIN", "internal")

	issuerClient, err := issuer.Login(ctx, vaultAddr, roleID, secretID)
	if err != nil {
		log.Fatalf("probe run: vault login: %v", err)
	}

	profileURLs, err := executor.ParseURLs(env("PROBE_EXECUTORS", ""))
	if err != nil {
		log.Fatalf("probe run: %v", err)
	}
	profileRegistry, err := executor.ApplyRemote(registry, profileURLs)
	if err != nil {
		log.Fatalf("probe run: %v", err)
	}
	r := &runner.Runner{
		Issuer:    issuerClient,
		Config:    cfg,
		Profiles:  profileRegistry,
		Scenarios: scenarioRegistry,
		Scenario:  selectedScenario.ID,
		OCSPURL:   vaultPublicAddr + "/v1/pki_int/ocsp",
		// Delta CRLs require base+delta merge semantics. The oracle consumes
		// the complete issuer-signed CRL as its standalone source of truth.
		CRLURL:            vaultPublicAddr + "/v1/pki_int/crl",
		IssuerEndpoint:    vaultAddr,
		Domain:            domain,
		CanaryBindHost:    env("PROBE_CANARY_BIND_HOST", ""),
		CanaryConnectHost: env("PROBE_CANARY_CONNECT_HOST", ""),
		EvidenceDir:       env("EVIDENCE_DIR", "/var/lib/pki-sentinel/evidence"),
		ExecutorURLs:      profileURLs,
	}

	runCycle := func() error {
		report, err := r.RunOnce(ctx)
		if report != nil {
			canonicalJSON, marshalErr := report.CanonicalJSON()
			if marshalErr != nil {
				return marshalErr
			}
			if archiveErr := r.ArchiveCycleReport(report.CycleID, canonicalJSON); archiveErr != nil {
				return fmt.Errorf("archive cycle report: %w", archiveErr)
			}
			if latestErr := r.UpdateLatestCycleReport(canonicalJSON); latestErr != nil {
				return fmt.Errorf("update latest cycle report: %w", latestErr)
			}
			if len(attestationPrivateKey) > 0 {
				attestationJSON, signErr := marshalAttestation(attestationPrivateKey, canonicalJSON)
				if signErr != nil {
					return fmt.Errorf("write assurance attestation: %w", signErr)
				}
				if archiveErr := r.ArchiveCycleAttestation(report.CycleID, attestationJSON); archiveErr != nil {
					return fmt.Errorf("archive cycle attestation: %w", archiveErr)
				}
				if latestErr := r.UpdateLatestCycleAttestation(attestationJSON); latestErr != nil {
					return fmt.Errorf("update latest cycle attestation: %w", latestErr)
				}
				if writeErr := writeAttestation(*attestationOut, attestationJSON); writeErr != nil {
					return fmt.Errorf("write assurance attestation: %w", writeErr)
				}
			}
			if printErr := writeReport(os.Stdout, report, *output, canonicalJSON, !*once); printErr != nil {
				return fmt.Errorf("write cycle report: %w", printErr)
			}
		}
		return err
	}

	if *once {
		if err := runCycle(); err != nil {
			log.Fatalf("probe run: cycle error: %v", err)
		}
		return
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	if err := runCycle(); err != nil {
		log.Printf("probe run: cycle error: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := runCycle(); err != nil {
				log.Printf("probe run: cycle error: %v", err)
			}
		}
	}
}

func marshalAttestation(privateKey, canonicalJSON []byte) ([]byte, error) {
	envelope, err := attestation.SignJSON(privateKey, canonicalJSON, time.Now())
	if err != nil {
		return nil, err
	}
	contents, err := attestation.MarshalEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

func writeAttestation(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".assurance-attestation-*")
	if err != nil {
		return fmt.Errorf("create temporary attestation: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary attestation permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary attestation: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary attestation: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary attestation: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace attestation: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open attestation directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync attestation directory: %w", err)
	}
	return nil
}

func writeReport(w io.Writer, report *runner.CycleReport, format string, canonicalJSON []byte, delimitJSON bool) error {
	if format == "json" {
		if _, err := w.Write(canonicalJSON); err != nil {
			return err
		}
		// A newline is stream framing, not part of the canonical report. The
		// one-shot path omits it so captured stdout is byte-identical to the
		// signed attestation payload; continuous mode needs it between cycles.
		if delimitJSON {
			_, err := w.Write([]byte{'\n'})
			return err
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "cycle %s  scenario=%s  revoke_ack_at=%s\n", report.CycleID, report.Scenario, report.RevokeAckAt.Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%-22s %-16s %-14s %-18s %-20s %-8s %s\n", "PROFILE", "ROLE", "METHOD", "DECISION", "REASON", "MATCH", "LATENCY"); err != nil {
		return err
	}
	for _, res := range report.Results {
		latency := res.DecisionLatency.Round(time.Millisecond).String()
		if _, err := fmt.Fprintf(w, "%-22s %-16s %-14s %-18s %-20s %-8t %s\n", res.Profile, res.Role, res.Method, res.Decision, res.Reason, res.ExpectationMet, latency); err != nil {
			return err
		}
	}
	return nil
}

// --- check (standalone single-profile invocation) -----------------------

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	profileName := fs.String("profile", "", "profile name, e.g. curl-default")
	target := fs.String("target", "", "https://host:port")
	caPath := fs.String("ca", "", "path to CA chain PEM")
	ocspURL := fs.String("ocsp-url", "", "OCSP responder URL required by direct OCSP profiles")
	crlURL := fs.String("crl-url", "", "CRL URL required by CRL profiles")
	leafSHA256 := fs.String("leaf-sha256", "", "expected SHA-256 of the exact leaf DER (required by status-oracle profiles)")
	_ = fs.Parse(args)

	if *profileName == "" || *target == "" || *caPath == "" {
		fmt.Fprintln(os.Stderr, "check: --profile, --target, and --ca are all required")
		os.Exit(2)
	}

	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		log.Fatalf("check: reading --ca: %v", err)
	}

	host, port, err := splitHostPort(*target)
	if err != nil {
		log.Fatalf("check: parsing --target: %v", err)
	}

	var found *profiles.Profile
	for _, p := range profiles.Registry() {
		if p.Name == *profileName {
			pp := p
			found = &pp
			break
		}
	}
	if found == nil {
		log.Fatalf("check: unknown profile %q", *profileName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if found.Method == profiles.MethodOCSPDirect && *ocspURL == "" {
		log.Fatal("check: --ocsp-url is required for an OCSP-direct profile")
	}
	if found.Method == profiles.MethodCRL && *crlURL == "" {
		log.Fatal("check: --crl-url is required for a CRL profile")
	}
	if found.Role == profiles.RoleStatusOracle && *leafSHA256 == "" {
		log.Fatal("check: --leaf-sha256 is required for a status-oracle profile so the observation is bound to the intended certificate")
	}
	t := profiles.Target{
		Host: host, Port: port, CAChainPEM: string(caPEM), IssuerPEM: string(caPEM),
		OCSPURL: *ocspURL, CRLURL: *crlURL, IssuedLeafSHA256: *leafSHA256, Scenario: profiles.Scenario("standalone_check"),
	}
	observation, err := found.Probe(ctx, t)
	if err != nil {
		fmt.Printf("decision=%s reason=%s err=%v\n", profiles.DecisionHarnessError, profiles.ReasonHarnessFailure, err)
		os.Exit(1)
	}
	fmt.Printf("decision=%s reason=%s\n", observation.Decision, observation.Reason)
}

// --- attest ---------------------------------------------------------------

func cmdAttest(args []string) {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: probe attest verify --public-key attestation.pub --input cycle.attestation.json")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("attest verify", flag.ExitOnError)
	publicKeyPath := fs.String("public-key", "", "Ed25519 PKIX public-key PEM")
	inputPath := fs.String("input", "", "attestation envelope JSON")
	_ = fs.Parse(args[1:])
	if *publicKeyPath == "" || *inputPath == "" {
		log.Fatal("attest verify: --public-key and --input are required")
	}
	publicKey, err := os.ReadFile(*publicKeyPath)
	if err != nil {
		log.Fatalf("attest verify: reading public key: %v", err)
	}
	envelope, err := attestation.ReadEnvelope(*inputPath)
	if err != nil {
		log.Fatalf("attest verify: %v", err)
	}
	if err := attestation.Verify(publicKey, envelope); err != nil {
		log.Fatalf("attest verify: %v", err)
	}
	fmt.Printf("verified %s issued_at=%s payload_sha256=%s\n", envelope.Statement.Version, envelope.Statement.IssuedAt.Format(time.RFC3339), envelope.Statement.PayloadSHA256)
}

// --- executor -------------------------------------------------------------

func cmdExecutor(args []string) {
	fs := flag.NewFlagSet("executor", flag.ExitOnError)
	profileName := fs.String("profile", "", "single profile to execute")
	listen := fs.String("listen", ":8120", "internal HTTP listen address")
	_ = fs.Parse(args)
	if *profileName == "" {
		log.Fatal("executor: --profile is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := executor.Serve(ctx, *listen, *profileName); err != nil {
		log.Fatalf("executor: %v", err)
	}
}

func splitHostPort(target string) (string, int, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return "", 0, fmt.Errorf("parsing URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" && parsed.Path != "/" {
		return "", 0, fmt.Errorf("expected https://host:port, got %q", target)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		return "", 0, fmt.Errorf("expected explicit host:port in %q: %w", target, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portText, err)
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range", port)
	}
	return host, port, nil
}

// --- chaos ---------------------------------------------------------------

func cmdChaos(args []string) {
	if len(args) == 0 || args[0] != "sweep" {
		fmt.Fprintln(os.Stderr, "usage: probe chaos sweep [--delays 0,1000,2000] [--trials 5] [--out path.csv]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("chaos sweep", flag.ExitOnError)
	delaysFlag := fs.String("delays", "", "comma-separated delay list in ms (default: dense sweep near 2s)")
	trials := fs.Int("trials", 5, "trials per delay level")
	out := fs.String("out", "", "output CSV path (default: docs/benchmarks/data/chaos-<timestamp>.csv)")
	scenarioID := fs.String("scenario", "missing_staple", "scenario manifest ID to execute")
	_ = fs.Parse(args[1:])
	if *trials < 1 {
		log.Fatal("chaos sweep: --trials must be at least 1")
	}

	delays := chaos.DefaultDelaysMS
	if *delaysFlag != "" {
		delays = nil
		for _, s := range strings.Split(*delaysFlag, ",") {
			v, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				log.Fatalf("chaos sweep: invalid --delays entry %q: %v", s, err)
			}
			delays = append(delays, v)
		}
	}

	outPath := *out
	if outPath == "" {
		outPath = fmt.Sprintf("docs/benchmarks/data/chaos-%d.csv", time.Now().Unix())
	}

	vaultAddr := env("VAULT_ADDR", "http://vault:8200")
	vaultPublicAddr := env("VAULT_PUBLIC_ADDR", "http://localhost:8200")
	roleID := env("VAULT_ROLE_ID", "")
	secretID := env("VAULT_SECRET_ID", "")
	domain := env("PKI_DOMAIN", "internal")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	const ocspPath = "/v1/pki_int/ocsp"
	faultProxy, err := chaos.StartLatencyProxy(vaultPublicAddr, ocspPath)
	if err != nil {
		log.Fatalf("chaos sweep: starting responder fault proxy: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := faultProxy.Close(shutdownCtx); err != nil {
			log.Printf("chaos sweep: closing responder fault proxy: %v", err)
		}
	}()

	issuerClient, err := issuer.Login(ctx, vaultAddr, roleID, secretID)
	if err != nil {
		log.Fatalf("chaos sweep: vault login: %v", err)
	}
	cfg := &config.Config{PollInterval: 2 * time.Second, MaxWait: 30 * time.Second, MaxAttempts: 15, PreflightMaxAge: 2 * time.Second, OCSPFreshness: config.OCSPFreshnessConfig{MaxClockSkew: 5 * time.Minute, RequireNextUpdate: true, MaxAgeWithoutNextUpdate: time.Hour}}
	for _, p := range profiles.Registry() {
		if p.Name == "openssl-ocsp-direct" {
			cfg.Profiles = append(cfg.Profiles, config.ProfileConfig{Name: p.Name, Enabled: true})
		}
	}

	scenarioRegistry, err := scenarios.LoadDir("scenarios", profiles.Registry())
	if err != nil {
		log.Fatalf("chaos sweep: loading scenarios: %v", err)
	}
	if err := scenarioRegistry.ValidateEnabledProfiles(cfg.EnabledNames()); err != nil {
		log.Fatalf("chaos sweep: validating scenarios: %v", err)
	}
	selectedScenario, ok := scenarioRegistry.Manifest(profiles.Scenario(*scenarioID))
	if !ok {
		log.Fatalf("chaos sweep: selected scenario %q is not loaded", *scenarioID)
	}
	if selectedScenario.Stapling != scenarios.StaplingOff {
		log.Fatalf("chaos sweep: scenario %q requires stapling mode %q; this command supports only off", selectedScenario.ID, selectedScenario.Stapling)
	}
	r := &runner.Runner{
		Issuer:      issuerClient,
		Config:      cfg,
		Profiles:    profiles.Registry(),
		Scenarios:   scenarioRegistry,
		Scenario:    selectedScenario.ID,
		OCSPURL:     faultProxy.URL() + ocspPath,
		CRLURL:      vaultPublicAddr + "/v1/pki_int/crl",
		Domain:      domain,
		EvidenceDir: env("EVIDENCE_DIR", "/var/lib/pki-sentinel/evidence"),
	}

	sweep, err := chaos.SweepDetailed(ctx, faultProxy, delays, *trials, func(trialCtx context.Context, delayMS int) (chaos.TrialOutcome, error) {
		report, err := r.RunOnce(trialCtx)
		if report == nil {
			return chaos.TrialOutcome{}, err
		}
		for _, res := range report.Results {
			if res.Profile == "openssl-ocsp-direct" {
				return chaos.TrialOutcome{
					Valid:    res.Decision != profiles.DecisionHarnessError && res.Err == "",
					Failed:   res.Decision != profiles.DecisionReject,
					Decision: string(res.Decision), Reason: string(res.Reason),
				}, nil
			}
		}
		return chaos.TrialOutcome{}, fmt.Errorf("openssl-ocsp-direct result missing from cycle report")
	})
	if err != nil {
		log.Printf("chaos sweep: %v", err)
	}

	if err := chaos.WriteDetailedCSV(outPath, sweep); err != nil {
		log.Fatalf("chaos sweep: writing CSV: %v", err)
	}
	fmt.Printf("wrote %s\n", outPath)
}
