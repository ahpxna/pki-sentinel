package executor

import (
	"testing"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

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
