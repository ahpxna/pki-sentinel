// Command probe is the revocation-probe CLI: `run` executes cycles on a
// schedule (or once, with --once), `check` runs a single profile standalone
// against an arbitrary target, and `chaos` sweeps injected OCSP-path
// latency and records the soft-fail rate at each level.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/canary"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/chaos"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/config"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/issuer"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/metrics"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/runner"
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
  probe run   [--once] [--config profiles.yaml] [--output json]
  probe check --profile <name> --target <https://host:port> --ca <chain.pem>
  probe chaos sweep [--delays 0,1000,2000] [--trials 5] [--out path.csv]`)
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
	output := fs.String("output", "text", "output format: text|json")
	interval := fs.Duration("interval", 15*time.Minute, "cycle interval when not --once")
	stapling := fs.String("stapling", "on", "OCSP stapling mode: on|off|stale")
	metricsAddr := fs.String("metrics-addr", ":9110", "address to serve /metrics, /healthz, /readyz")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("probe run: %v", err)
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

	r := &runner.Runner{
		Issuer:   issuerClient,
		Config:   cfg,
		Profiles: profiles.Registry(),
		Stapling: canary.StaplingMode(*stapling),
		OCSPURL:  vaultPublicAddr + "/v1/pki_int/ocsp",
		// The demo enables Vault delta CRLs with a one-minute rebuild
		// interval; the full CRL is intentionally long-lived (72h).
		CRLURL: vaultPublicAddr + "/v1/pki_int/crl/delta",
		Domain: domain,
	}

	runCycle := func() error {
		report, err := r.RunOnce(ctx)
		if err != nil {
			return err
		}
		printReport(report, *output)
		return nil
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

func printReport(report *runner.CycleReport, format string) {
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}
	fmt.Printf("cycle %s  revoked_at=%s\n", report.CycleID, report.RevokedAt.Format(time.RFC3339))
	fmt.Printf("%-22s %-14s %-10s %-10s %s\n", "PROFILE", "METHOD", "OUTCOME", "ATTEMPTS", "DETECTION")
	for _, res := range report.Results {
		det := "-"
		if res.Outcome == profiles.OutcomeRejected {
			det = res.DetectionDur.Round(time.Millisecond).String()
		}
		fmt.Printf("%-22s %-14s %-10s %-10d %s\n", res.Profile, res.Method, res.Outcome, res.Attempts, det)
	}
}

// --- check (standalone single-profile invocation) -----------------------

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	profileName := fs.String("profile", "", "profile name, e.g. curl-default")
	target := fs.String("target", "", "https://host:port")
	caPath := fs.String("ca", "", "path to CA chain PEM")
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

	t := profiles.Target{Host: host, Port: port, CAChainPEM: string(caPEM), IssuerPEM: string(caPEM)}
	outcome, err := found.Probe(ctx, t)
	if err != nil {
		fmt.Printf("outcome=error err=%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("outcome=%s\n", outcome)
}

func splitHostPort(target string) (string, int, error) {
	t := strings.TrimPrefix(target, "https://")
	t = strings.TrimSuffix(t, "/")
	parts := strings.SplitN(t, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("expected host:port, got %q", target)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", parts[1], err)
	}
	return parts[0], port, nil
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
	iface := fs.String("iface", "eth0", "network interface to apply netem to")
	_ = fs.Parse(args[1:])

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

	issuerClient, err := issuer.Login(ctx, vaultAddr, roleID, secretID)
	if err != nil {
		log.Fatalf("chaos sweep: vault login: %v", err)
	}
	cfg := &config.Config{PollInterval: 2 * time.Second, MaxWait: 30 * time.Second}
	for _, p := range profiles.Registry() {
		if p.Name == "openssl-ocsp-direct" {
			cfg.Profiles = append(cfg.Profiles, config.ProfileConfig{Name: p.Name, Enabled: true})
		}
	}

	r := &runner.Runner{
		Issuer:   issuerClient,
		Config:   cfg,
		Profiles: profiles.Registry(),
		Stapling: canary.StaplingOff,
		OCSPURL:  vaultPublicAddr + "/v1/pki_int/ocsp",
		CRLURL:   vaultPublicAddr + "/v1/pki_int/crl/delta",
		Domain:   domain,
	}

	results, err := chaos.Sweep(ctx, *iface, delays, *trials, func(trialCtx context.Context, delayMS int) (bool, error) {
		report, err := r.RunOnce(trialCtx)
		if err != nil {
			return false, err
		}
		for _, res := range report.Results {
			if res.Profile == "openssl-ocsp-direct" {
				return res.Outcome != profiles.OutcomeRejected, nil
			}
		}
		return false, fmt.Errorf("openssl-ocsp-direct result missing from cycle report")
	})
	if err != nil {
		log.Printf("chaos sweep: %v", err)
	}

	for _, d := range delays {
		if rate, ok := results[d]; ok {
			metrics.ChaosSoftfailRate.WithLabelValues(strconv.Itoa(d)).Set(rate)
		}
	}

	if err := chaos.WriteCSV(outPath, delays, results); err != nil {
		log.Fatalf("chaos sweep: writing CSV: %v", err)
	}
	fmt.Printf("wrote %s\n", outPath)
}
