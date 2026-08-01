// Package metrics defines and serves the Prometheus metrics exported by
// revocation-probe. Metric names are a stable contract: Grafana dashboards
// and CI assertions in later phases depend on them verbatim — do not rename.
package metrics

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	DetectionSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pki_revocation_detection_seconds",
		Help:    "Time from revocation to a profile detecting rejection.",
		Buckets: []float64{1, 2, 5, 10, 15, 30, 60, 120, 180},
	}, []string{"profile", "method", "stapling"})

	SoftfailTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pki_revocation_softfail_total",
		Help: "Count of cycles where a profile accepted a revoked certificate.",
	}, []string{"profile", "method", "stapling"})

	DetectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pki_revocation_detected_total",
		Help: "Count of cycles where a profile correctly rejected a revoked certificate.",
	}, []string{"profile", "method", "stapling"})

	CycleTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pki_revocation_cycle_total",
		Help: "Count of probe cycles by result (ok|error).",
	}, []string{"result"})

	LastCycleTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pki_revocation_last_cycle_timestamp_seconds",
		Help: "Unix timestamp of the last completed probe cycle.",
	})

	OCSPResponderLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "pki_ocsp_responder_latency_seconds",
		Help:    "Observed latency of the OCSP responder as measured by the ground-truth oracle profile.",
		Buckets: prometheus.DefBuckets,
	})

	OCSPResponderUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pki_ocsp_responder_up",
		Help: "1 if the OCSP responder answered the last query, 0 otherwise.",
	})

	CRLAgeSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pki_crl_age_seconds",
		Help: "Age of the current CRL (now - ThisUpdate), in seconds.",
	})

	CRLEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pki_crl_entries",
		Help: "Number of revoked certificate entries in the current CRL.",
	})

	CertNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pki_cert_not_after_timestamp_seconds",
		Help: "NotAfter timestamp (unix seconds) of a tracked certificate.",
	}, []string{"cn", "serial", "source"})

	ChaosSoftfailRate = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pki_chaos_softfail_rate",
		Help: "Soft-fail rate observed at a given injected OCSP-path delay, from --chaos sweeps.",
	}, []string{"delay_ms"})
)

// Serve starts the metrics/health HTTP server and blocks until ctx is
// cancelled.
func Serve(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("metrics: serving on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
