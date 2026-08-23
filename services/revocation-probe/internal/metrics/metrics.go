// Package metrics defines and serves the Prometheus metrics exported by
// revocation-probe. Labels are intentionally bounded; certificate serials,
// random hostnames, and raw evidence belong in JSON records rather than TSDB
// labels.
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

	AssuranceObservations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pki_assurance_observations_total",
		Help: "Count of assurance observations by bounded decision and reason dimensions.",
	}, []string{"profile", "role", "method", "scenario", "decision", "reason"})

	CycleTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pki_revocation_cycle_total",
		Help: "Count of probe cycles by result (ok|error|regression).",
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

	CertNotAfter = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pki_cert_not_after_timestamp_seconds",
		Help: "NotAfter timestamp (unix seconds) of the current ephemeral canary certificate.",
	})

)

// RecordObservation records bounded assurance dimensions. Unbounded evidence
// such as certificate serials and output hashes is retained only in JSON.
func RecordObservation(profile, role, method, scenario, decision, reason string) {
	AssuranceObservations.WithLabelValues(profile, role, method, scenario, decision, reason).Inc()
}

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

	srv := &http.Server{
		Addr:              addr,
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

	log.Printf("metrics: serving on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
