package chaos

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLatencyProxyScopesDelayToAllowedPath(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ocsp")
	}))
	defer upstream.Close()

	proxy, err := StartLatencyProxy(upstream.URL, "/v1/pki_int/ocsp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := proxy.Close(ctx); err != nil {
			t.Errorf("close proxy: %v", err)
		}
	})

	if err := proxy.SetDelay(80 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, err := http.Get(proxy.URL() + "/v1/pki_int/ocsp") // #nosec G107 -- local test server
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if elapsed := time.Since(started); elapsed < 60*time.Millisecond {
		t.Fatalf("request was not delayed: %s", elapsed)
	}

	notFound, err := http.Get(proxy.URL() + "/v1/sys/health") // #nosec G107 -- local test server
	if err != nil {
		t.Fatal(err)
	}
	defer notFound.Body.Close()
	if notFound.StatusCode != http.StatusNotFound {
		t.Fatalf("disallowed path status = %d, want 404", notFound.StatusCode)
	}
}

func TestLatencyProxyInjectsResponderFaults(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ocsp")
	}))
	defer upstream.Close()

	proxy, err := StartLatencyProxy(upstream.URL, "/v1/pki_int/ocsp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := proxy.Close(ctx); err != nil {
			t.Errorf("close proxy: %v", err)
		}
	})

	if err := proxy.SetFault(Fault{Mode: FaultHTTP500}); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(proxy.URL() + "/v1/pki_int/ocsp") // #nosec G107 -- local test server
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("http_500 status = %d, want 500", response.StatusCode)
	}

	if err := proxy.SetFault(Fault{Mode: FaultMalformed}); err != nil {
		t.Fatal(err)
	}
	response, err = http.Get(proxy.URL() + "/v1/pki_int/ocsp") // #nosec G107 -- local test server
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "not-a-valid-ocsp-response" {
		t.Fatalf("malformed response = %d/%q", response.StatusCode, body)
	}

	if err := proxy.SetFault(Fault{Mode: FaultTimeout, Delay: 100 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 20 * time.Millisecond}
	if _, err := client.Get(proxy.URL() + "/v1/pki_int/ocsp"); err == nil { // #nosec G107 -- local test server
		t.Fatal("timeout fault unexpectedly returned a response")
	}

	if err := proxy.SetFault(Fault{Mode: FaultDrop}); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get(proxy.URL() + "/v1/pki_int/ocsp"); err == nil { // #nosec G107 -- local test server
		t.Fatal("drop fault unexpectedly returned a response")
	}
	if err := proxy.SetFault(Fault{Mode: FaultReset}); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get(proxy.URL() + "/v1/pki_int/ocsp"); err == nil { // #nosec G107 -- local test server
		t.Fatal("reset fault unexpectedly returned a response")
	}
}

func TestSetFaultRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	proxy := &LatencyProxy{}
	if err := proxy.SetFault(Fault{Mode: "unexpected"}); err == nil {
		t.Fatal("SetFault accepted an unknown mode")
	}
	if err := proxy.SetFault(Fault{Mode: FaultDelay, Delay: -time.Second}); err == nil {
		t.Fatal("SetFault accepted a negative delay")
	}
	if err := proxy.SetDelay(-time.Second); err == nil {
		t.Fatal("SetDelay accepted a negative delay")
	}
}

type recordingController struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (c *recordingController) SetDelay(delay time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.delays = append(c.delays, delay)
	return nil
}

func TestSweepRecordsFailuresAndResetsDelay(t *testing.T) {
	t.Parallel()
	controller := &recordingController{}
	results, err := Sweep(context.Background(), controller, []int{0, 20}, 2, func(_ context.Context, delay int) (bool, error) {
		return delay == 20, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if results[0] != 0 || results[20] != 1 {
		t.Fatalf("unexpected results: %#v", results)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if got := controller.delays; len(got) != 3 || got[2] != 0 {
		t.Fatalf("delay sequence = %v, want final reset", got)
	}
}

func TestSweepRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	controller := &recordingController{}
	trial := func(context.Context, int) (bool, error) { return false, nil }
	if _, err := Sweep(context.Background(), controller, nil, 0, trial); err == nil || !strings.Contains(err.Error(), "trials") {
		t.Fatalf("expected trials validation error, got %v", err)
	}
	if _, err := Sweep(context.Background(), controller, []int{-1}, 1, trial); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("expected delay validation error, got %v", err)
	}
}

type rejectingController struct{}

func (rejectingController) SetDelay(delay time.Duration) error {
	if delay == 0 {
		return nil
	}
	return errors.New("fault controller rejected delay")
}

func TestSweepDetailedPropagatesControllerFailure(t *testing.T) {
	t.Parallel()
	_, err := SweepDetailed(context.Background(), rejectingController{}, []int{10}, 1, func(context.Context, int) (TrialOutcome, error) {
		return TrialOutcome{Valid: true}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "setting delay") {
		t.Fatalf("expected controller error, got %v", err)
	}
}

func TestSweepResetsDelayOnCancellation(t *testing.T) {
	t.Parallel()
	controller := &recordingController{}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := Sweep(ctx, controller, []int{10, 20}, 1, func(context.Context, int) (bool, error) {
		cancel()
		return false, nil
	})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if got := controller.delays[len(controller.delays)-1]; got != 0 {
		t.Fatalf("final delay = %s, want 0", got)
	}
}

func TestSweepDetailedSeparatesHarnessErrorsFromFailures(t *testing.T) {
	t.Parallel()
	controller := &recordingController{}
	attempt := 0
	sweep, err := SweepDetailed(context.Background(), controller, []int{10}, 3, func(_ context.Context, _ int) (TrialOutcome, error) {
		attempt++
		switch attempt {
		case 1:
			return TrialOutcome{Valid: true, Failed: true, Decision: "ACCEPT", Reason: "STATUS_GOOD"}, nil
		case 2:
			return TrialOutcome{Valid: true, Failed: false, Decision: "REJECT", Reason: "REVOKED"}, nil
		default:
			return TrialOutcome{}, errors.New("executor unavailable")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	stats := sweep.Stats[10]
	if stats.Attempted != 3 || stats.ValidTrials != 2 || stats.Failures != 1 || stats.HarnessErrors != 1 || stats.FailureRate() != 0.5 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	if len(sweep.Trials) != 3 || sweep.Trials[2].HarnessError == "" {
		t.Fatalf("unexpected trials: %#v", sweep.Trials)
	}
}
