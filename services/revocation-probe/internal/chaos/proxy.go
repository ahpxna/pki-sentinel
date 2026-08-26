// Package chaos implements responder-scoped fault injection for assurance
// experiments. The latency proxy accepts only the configured OCSP path, so a
// sweep cannot delay the probe's issuer, CRL, or target-service traffic.
package chaos

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultDelaysMS retains the dense sampling points used by the prior
// private-CA experiment. Results from the current direct-OCSP oracle sweep
// are not equivalent to relying-party soft-fail measurements.
var DefaultDelaysMS = []int{0, 100, 500, 1000, 1500, 1700, 1900, 1950, 1960, 1970, 1980, 1990, 2000}

// FaultMode is the bounded responder fault applied by a FaultProxy. The proxy
// intentionally operates at HTTP/TCP boundaries rather than using tc, so it
// needs neither NET_ADMIN nor access outside its loopback listener.
type FaultMode string

const (
	FaultPassThrough FaultMode = "pass_through"
	FaultDelay       FaultMode = "delay"
	FaultDrop        FaultMode = "drop"
	FaultTimeout     FaultMode = "timeout"
	FaultHTTP500     FaultMode = "http_500"
	FaultMalformed   FaultMode = "malformed_ocsp"
	FaultReset       FaultMode = "reset"
)

// Fault configures one responder behavior. Delay is used by delay and timeout
// modes. A timeout with a duration holds the connection for that interval and
// then closes it without an HTTP response; with no duration it waits until the
// caller cancels the request.
type Fault struct {
	Mode  FaultMode
	Delay time.Duration
}

func (f Fault) validate() error {
	switch f.Mode {
	case FaultPassThrough, FaultDelay, FaultDrop, FaultTimeout, FaultHTTP500, FaultMalformed, FaultReset:
	default:
		return fmt.Errorf("unsupported fault mode %q", f.Mode)
	}
	if f.Delay < 0 {
		return fmt.Errorf("fault delay must not be negative")
	}
	return nil
}

// LatencyProxy is a responder-scoped reverse proxy with an atomically
// adjustable fault. Only allowedPath is forwarded to upstream. Its historical
// name is kept for compatibility with the latency-sweep command.
type LatencyProxy struct {
	fault    atomic.Value // Fault
	listener net.Listener
	server   *http.Server
	baseURL  string
	done     chan error
}

// StartLatencyProxy starts a loopback-only proxy for one responder path.
func StartLatencyProxy(upstreamBase, allowedPath string) (*LatencyProxy, error) {
	upstream, err := url.Parse(upstreamBase)
	if err != nil {
		return nil, fmt.Errorf("parse upstream URL: %w", err)
	}
	if (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" {
		return nil, fmt.Errorf("upstream must be an absolute HTTP(S) URL")
	}
	if upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, fmt.Errorf("upstream URL must not contain credentials, query, or fragment")
	}
	if !strings.HasPrefix(allowedPath, "/") {
		return nil, fmt.Errorf("allowed path must be absolute")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for latency proxy: %w", err)
	}

	proxy := &LatencyProxy{
		listener: listener,
		baseURL:  "http://" + listener.Addr().String(),
		done:     make(chan error, 1),
	}
	proxy.fault.Store(Fault{Mode: FaultPassThrough})
	reverseProxy := httputil.NewSingleHostReverseProxy(upstream)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != allowedPath {
			http.NotFound(w, r)
			return
		}
		fault := proxy.Fault()
		switch fault.Mode {
		case FaultPassThrough:
			reverseProxy.ServeHTTP(w, r)
		case FaultDelay:
			if waitForRequest(r, fault.Delay) {
				reverseProxy.ServeHTTP(w, r)
			}
		case FaultDrop:
			// Close without a response. HTTP clients observe an interrupted
			// responder request rather than a valid status response.
			closeConnection(w, false)
		case FaultTimeout:
			if fault.Delay > 0 {
				if waitForRequest(r, fault.Delay) {
					// Returning from a net/http handler without writing a response
					// produces an implicit 200. A timeout fault must therefore
					// terminate the connection after the hold interval without
					// publishing any HTTP status.
					closeConnection(w, false)
				}
				return
			}
			<-r.Context().Done()
		case FaultHTTP500:
			http.Error(w, "injected OCSP responder failure", http.StatusInternalServerError)
		case FaultMalformed:
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-a-valid-ocsp-response"))
		case FaultReset:
			resetConnection(w)
		}
	})
	proxy.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		err := proxy.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		proxy.done <- err
		close(proxy.done)
	}()
	return proxy, nil
}

func waitForRequest(r *http.Request, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-r.Context().Done():
		return false
	case <-timer.C:
		return true
	}
}

func resetConnection(w http.ResponseWriter) {
	closeConnection(w, true)
}

func closeConnection(w http.ResponseWriter, reset bool) {
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		// If an HTTP implementation does not support hijacking, returning
		// without a response still makes the request fail closed.
		return
	}
	if reset {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
	}
	_ = conn.Close()
}

// URL returns the loopback base URL. Callers append the allowed responder
// path when configuring the oracle.
func (p *LatencyProxy) URL() string { return p.baseURL }

// SetDelay changes the delay applied to requests that arrive afterward.
// A zero delay restores pass-through behavior, which gives Sweep a reliable
// cleanup operation even when its context is cancelled.
func (p *LatencyProxy) SetDelay(delay time.Duration) error {
	mode := FaultDelay
	if delay == 0 {
		mode = FaultPassThrough
	}
	return p.SetFault(Fault{Mode: mode, Delay: delay})
}

// SetFault changes the responder behavior for requests that arrive afterward.
// Invalid configurations are rejected before any traffic is altered.
func (p *LatencyProxy) SetFault(fault Fault) error {
	if err := fault.validate(); err != nil {
		return err
	}
	p.fault.Store(fault)
	return nil
}

// Fault returns a snapshot of the active responder fault.
func (p *LatencyProxy) Fault() Fault {
	return p.fault.Load().(Fault)
}

// Close gracefully stops the proxy and reports an unexpected serve failure.
func (p *LatencyProxy) Close(ctx context.Context) error {
	shutdownErr := p.server.Shutdown(ctx)
	if shutdownErr != nil {
		// Shutdown can time out while an upstream request is still active.
		// Force-close so waiting for Serve below cannot deadlock the caller.
		_ = p.server.Close()
	}
	serveErr := <-p.done
	return errors.Join(shutdownErr, serveErr)
}

// delayController captures the only fault capability required by Sweep.
type delayController interface {
	SetDelay(time.Duration) error
}

// TrialOutcome keeps an experiment failure separate from a broken harness.
// Decision and Reason are deliberately bounded assurance values so they can
// be exported without introducing unbounded labels or CSV fields.
type TrialOutcome struct {
	Valid    bool
	Failed   bool
	Decision string
	Reason   string
}

// TrialRecord is one reproducible observation in a fault sweep.
type TrialRecord struct {
	Timestamp    time.Time
	DelayMS      int
	FaultMode    FaultMode
	Attempted    bool
	Valid        bool
	HarnessError string
	Failed       bool
	Decision     string
	Reason       string
}

// SweepStats contains denominators required to interpret a failure rate.
type SweepStats struct {
	Attempted     int
	ValidTrials   int
	HarnessErrors int
	Failures      int
}

func (s SweepStats) FailureRate() float64 {
	if s.ValidTrials == 0 {
		return 0
	}
	return float64(s.Failures) / float64(s.ValidTrials)
}

// DetailedSweep is both the human-auditable trial log and aggregate counts.
type DetailedSweep struct {
	Stats  map[int]SweepStats
	Trials []TrialRecord
}

// Sweep runs trials at each delay level and returns the fraction of trials in
// which the direct status oracle failed to confirm the expected decision.
func Sweep(ctx context.Context, controller delayController, delaysMS []int, trials int, runTrial func(context.Context, int) (bool, error)) (map[int]float64, error) {
	detailed, err := SweepDetailed(ctx, controller, delaysMS, trials, func(ctx context.Context, delay int) (TrialOutcome, error) {
		failed, err := runTrial(ctx, delay)
		return TrialOutcome{Valid: err == nil, Failed: failed}, err
	})
	if err != nil {
		return rates(detailed.Stats), err
	}
	return rates(detailed.Stats), nil
}

// SweepDetailed runs responder-scoped trials and records their validity,
// decision, reason, fault mode, and timestamp. Harness errors are excluded
// from the failure-rate denominator rather than being counted as soft-fails.
func SweepDetailed(ctx context.Context, controller delayController, delaysMS []int, trials int, runTrial func(context.Context, int) (TrialOutcome, error)) (DetailedSweep, error) {
	if controller == nil {
		return DetailedSweep{}, fmt.Errorf("chaos: delay controller is required")
	}
	if trials < 1 {
		return DetailedSweep{}, fmt.Errorf("chaos: trials must be at least 1")
	}
	defer func() {
		if err := controller.SetDelay(0); err != nil {
			log.Printf("chaos: failed to reset responder delay: %v", err)
		}
	}()

	result := DetailedSweep{Stats: make(map[int]SweepStats, len(delaysMS))}
	for _, delay := range delaysMS {
		if delay < 0 {
			return result, fmt.Errorf("chaos: delay must not be negative: %d", delay)
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		if err := controller.SetDelay(time.Duration(delay) * time.Millisecond); err != nil {
			return result, fmt.Errorf("chaos: setting delay %dms: %w", delay, err)
		}
		stats := SweepStats{}
		for range trials {
			mode := FaultDelay
			if delay == 0 {
				mode = FaultPassThrough
			}
			record := TrialRecord{Timestamp: time.Now().UTC(), DelayMS: delay, FaultMode: mode, Attempted: true}
			stats.Attempted++
			outcome, err := runTrial(ctx, delay)
			if err != nil {
				log.Printf("chaos: trial error at delay=%dms: %v", delay, err)
				stats.HarnessErrors++
				record.HarnessError = err.Error()
				result.Trials = append(result.Trials, record)
				continue
			}
			record.Valid, record.Failed, record.Decision, record.Reason = outcome.Valid, outcome.Failed, outcome.Decision, outcome.Reason
			if !outcome.Valid {
				stats.HarnessErrors++
				record.HarnessError = "trial returned invalid outcome"
			} else {
				stats.ValidTrials++
				if outcome.Failed {
					stats.Failures++
				}
			}
			result.Trials = append(result.Trials, record)
		}
		result.Stats[delay] = stats
		log.Printf("chaos: delay=%dms oracle_failure_rate=%.2f (%d/%d valid; %d harness errors)", delay, stats.FailureRate(), stats.Failures, stats.ValidTrials, stats.HarnessErrors)
	}
	return result, nil
}

func rates(stats map[int]SweepStats) map[int]float64 {
	result := make(map[int]float64, len(stats))
	for delay, value := range stats {
		result[delay] = value.FailureRate()
	}
	return result
}

// WriteCSV writes sweep results in caller-provided delay order.
func WriteCSV(path string, delaysMS []int, results map[int]float64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString("delay_ms,oracle_failure_rate\n"); err != nil {
		return err
	}
	for _, delay := range delaysMS {
		rate, ok := results[delay]
		if !ok {
			continue
		}
		if _, err := fmt.Fprintf(f, "%d,%.4f\n", delay, rate); err != nil {
			return err
		}
	}
	return nil
}

// WriteDetailedCSV writes one row per attempted trial. It is the evidence
// format for new experiments; WriteCSV is retained for existing consumers.
func WriteDetailedCSV(path string, sweep DetailedSweep) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString("timestamp,delay_ms,fault_mode,attempted,valid,decision,reason,harness_error,oracle_failure\n"); err != nil {
		return err
	}
	for _, trial := range sweep.Trials {
		if _, err := fmt.Fprintf(f, "%s,%d,%s,%t,%t,%s,%s,%q,%t\n", trial.Timestamp.Format(time.RFC3339Nano), trial.DelayMS, trial.FaultMode, trial.Attempted, trial.Valid, trial.Decision, trial.Reason, trial.HarnessError, trial.Failed); err != nil {
			return err
		}
	}
	return nil
}
