// Command demo-api is the reference "identity loop" service for pki-sentinel:
// it logs in to Vault via AppRole, reads a secret from KV-v2 (logging only
// its presence, never its value), requests a short-lived client certificate
// from pki_int/issue/client and renews it before expiry, and exposes
// /healthz, /whoami, and /metrics.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ahpxna/pki-sentinel/services/demo-api/internal/vaultauth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricCertExpiry = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "demo_api_cert_not_after_timestamp_seconds",
		Help: "NotAfter timestamp (unix seconds) of the current client certificate.",
	})
	metricTokenTTL = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "demo_api_vault_token_ttl_seconds",
		Help: "Remaining TTL of the current Vault token, as last observed.",
	})
	metricRenewals = promauto.NewCounter(prometheus.CounterOpts{
		Name: "demo_api_cert_renewals_total",
		Help: "Number of client certificate renewal attempts.",
	})
	metricRenewalFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "demo_api_cert_renewal_failures_total",
		Help: "Number of failed certificate renewal attempts.",
	})
)

type certState struct {
	mu         sync.RWMutex
	commonName string
	notAfter   time.Time
	certPEM    string
	keyPEM     string
}

func (c *certState) set(cn string, notAfter time.Time, certPEM, keyPEM string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commonName, c.notAfter, c.certPEM, c.keyPEM = cn, notAfter, certPEM, keyPEM
}

func (c *certState) get() (cn string, notAfter time.Time, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.commonName, c.notAfter, !c.notAfter.IsZero()
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	vaultAddr := getenv("VAULT_ADDR", "http://vault:8200")
	envFile := getenv("VAULT_APPROLE_ENV_FILE", "/run/secrets/demo-api.env")
	listenAddr := getenv("DEMO_API_LISTEN", ":8000")

	creds, err := vaultauth.LoadEnvFile(envFile)
	if err != nil {
		log.Fatalf("demo-api: %v", err)
	}

	vc, err := vaultauth.Login(ctx, vaultAddr, creds)
	if err != nil {
		log.Fatalf("demo-api: vault login failed: %v", err)
	}
	log.Printf("demo-api: approle login succeeded")
	reportTokenTTL(ctx, vc)

	// Read the KV-v2 secret once at boot. Log only presence, never the value.
	if secret, err := vc.API.Logical().ReadWithContext(ctx, "kv/data/demo-api/config"); err != nil {
		log.Printf("demo-api: WARNING: could not read kv/data/demo-api/config: %v", err)
	} else if secret != nil && secret.Data["data"] != nil {
		log.Printf("demo-api: secret loaded (kv/data/demo-api/config present)")
	} else {
		log.Printf("demo-api: WARNING: kv/data/demo-api/config returned no data")
	}

	state := &certState{}
	if err := issueCertificate(ctx, vc, state); err != nil {
		log.Fatalf("demo-api: initial cert issuance failed: %v", err)
	}
	go renewalController(ctx, vc, state)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		cn, notAfter, ok := state.get()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "no certificate issued yet"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"common_name": cn,
			"not_after":   notAfter.UTC().Format(time.RFC3339),
		})
	})
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("demo-api: listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("demo-api: server error: %v", err)
	}
}

// issueCertificate requests and atomically installs a fresh client certificate.
func issueCertificate(ctx context.Context, vc *vaultauth.Client, state *certState) error {
	secret, err := vc.API.Logical().WriteWithContext(ctx, "pki_int/issue/client", map[string]interface{}{
		"common_name": "demo-api.internal",
		"ttl":         "24h",
	})
	if err != nil {
		return err
	}
	certPEM, _ := secret.Data["certificate"].(string)
	keyPEM, _ := secret.Data["private_key"].(string)

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("issueCertificate: could not decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	state.set(cert.Subject.CommonName, cert.NotAfter, certPEM, keyPEM)
	metricCertExpiry.Set(float64(cert.NotAfter.Unix()))

	return nil
}

// renewalController keeps retrying after transient issuer failures. It never
// abandons renewal because a single Vault outage happened at the normal
// renewal deadline; retries accelerate as expiry approaches.
func renewalController(ctx context.Context, vc *vaultauth.Client, state *certState) {
	for {
		_, notAfter, ok := state.get()
		if !ok {
			return
		}
		wait := time.Until(notAfter) * 2 / 3
		if wait < time.Minute {
			wait = time.Minute
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		backoff := time.Second
		for {
			metricRenewals.Inc()
			if err := issueCertificate(ctx, vc, state); err == nil {
				log.Printf("demo-api: certificate renewed")
				break
			} else {
				metricRenewalFailures.Inc()
				log.Printf("demo-api: certificate renewal failed; retrying in %s: %v", backoff, err)
			}
			_, currentNotAfter, _ := state.get()
			remaining := time.Until(currentNotAfter)
			if remaining <= 0 {
				backoff = time.Second
			} else if remaining < 5*time.Minute {
				backoff = minDuration(backoff, 15*time.Second)
			} else {
				backoff = minDuration(backoff*2, time.Minute)
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// reportTokenTTL sets metricTokenTTL from the current token's self-lookup
// and keeps it refreshed every minute for the lifetime of ctx.
func reportTokenTTL(ctx context.Context, vc *vaultauth.Client) {
	update := func() {
		secret, err := vc.API.Auth().Token().LookupSelfWithContext(ctx)
		if err != nil || secret == nil {
			return
		}
		switch ttl := secret.Data["ttl"].(type) {
		case json.Number:
			if f, err := ttl.Float64(); err == nil {
				metricTokenTTL.Set(f)
			}
		case float64:
			metricTokenTTL.Set(ttl)
		}
	}
	update()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				update()
			}
		}
	}()
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
