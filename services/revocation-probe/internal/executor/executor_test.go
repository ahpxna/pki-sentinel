package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestParseURLs(t *testing.T) {
	t.Parallel()
	urls, err := ParseURLs("curl-default=http://client-curl:8120,go-tls-default=http://client-go:8120")
	if err != nil {
		t.Fatal(err)
	}
	if urls["curl-default"] != "http://client-curl:8120" || len(urls) != 2 {
		t.Fatalf("unexpected parsed URLs: %#v", urls)
	}
	if _, err := ParseURLs("broken"); err == nil {
		t.Fatal("expected malformed entry error")
	}
	if _, err := ParseURLs("curl-default=file:///tmp/socket"); err == nil {
		t.Fatal("expected non-HTTP executor URL to be rejected")
	}
	if _, err := ParseURLs("curl-default=http://client:8120/base"); err == nil {
		t.Fatal("expected executor URL with path prefix to be rejected")
	}
}

func TestValidateTargetRestrictsExecutorDestinations(t *testing.T) {
	t.Setenv("EXECUTOR_ALLOWED_CONNECT_HOST", "revocation-probe")
	t.Setenv("EXECUTOR_ALLOWED_STATUS_HOST", "vault")
	target := profiles.Target{
		ConnectHost: "revocation-probe",
		OCSPURL:     "http://vault/v1/pki_int/ocsp",
		CRLURL:      "http://vault/v1/pki_int/crl",
	}
	if err := validateTarget(target); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	target.OCSPURL = "http://metadata.internal/v1/token"
	if err := validateTarget(target); err == nil {
		t.Fatal("unapproved status host accepted")
	}
}

func TestApplyRemoteRequiresToken(t *testing.T) {
	t.Setenv("PROBE_EXECUTOR_TOKEN", "")
	t.Setenv("ALLOW_UNAUTHENTICATED_EXECUTOR", "")
	registry := []profiles.Profile{{Name: "curl-default"}}
	if _, err := ApplyRemote(registry, map[string]string{"curl-default": "http://client:8120"}); err == nil {
		t.Fatal("remote executor configuration was accepted without authentication")
	}
	t.Setenv("PROBE_EXECUTOR_TOKEN", "test-token")
	if _, err := ApplyRemote(registry, map[string]string{"curl-default": "http://client:8120"}); err != nil {
		t.Fatalf("authenticated remote executor configuration rejected: %v", err)
	}
}

func TestRequiredExecutorTokenAllowsExplicitLocalOptOut(t *testing.T) {
	t.Setenv("PROBE_EXECUTOR_TOKEN", "")
	t.Setenv("ALLOW_UNAUTHENTICATED_EXECUTOR", "1")
	if token, err := requiredExecutorToken(); err != nil || token != "" {
		t.Fatalf("explicit local opt-out rejected: token=%q err=%v", token, err)
	}
}

func TestRemotePreservesExecutorHarnessError(t *testing.T) {
	t.Setenv("PROBE_EXECUTOR_TOKEN", "test-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(profiles.Observation{
			Decision:     profiles.DecisionHarnessError,
			Reason:       profiles.ReasonHarnessFailure,
			HarnessError: "openssl exited with status 2",
		})
	}))
	defer server.Close()

	profile := Remote(profiles.Profile{Name: "openssl-ocsp-direct"}, server.URL)
	observation, err := profile.Probe(context.Background(), profiles.Target{})
	if err == nil || !strings.Contains(err.Error(), "openssl exited with status 2") {
		t.Fatalf("Probe error=%v, want remote harness cause", err)
	}
	if observation.Decision != profiles.DecisionHarnessError || observation.Reason != profiles.ReasonHarnessFailure {
		t.Fatalf("unexpected observation: %#v", observation)
	}
}

func TestRemoteCarriesControllerConfiguredTimeout(t *testing.T) {
	t.Setenv("PROBE_EXECUTOR_TOKEN", "test-token")
	originalTransport := executorHTTPClient.Transport
	defer func() { executorHTTPClient.Transport = originalTransport }()
	wantTimeout := 27 * time.Second
	executorHTTPClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var target profiles.Target
		if err := json.NewDecoder(request.Body).Decode(&target); err != nil {
			t.Fatal(err)
		}
		if target.ProbeTimeout != wantTimeout {
			t.Fatalf("probe timeout=%s, want %s", target.ProbeTimeout, wantTimeout)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"decision":"ACCEPT","reason":"STATUS_GOOD"}`))}, nil
	})
	profile := Remote(profiles.Profile{Name: "curl-default"}, "http://executor.invalid")
	if _, err := profile.Probe(context.Background(), profiles.Target{ProbeTimeout: wantTimeout}); err != nil {
		t.Fatalf("remote probe: %v", err)
	}
}
