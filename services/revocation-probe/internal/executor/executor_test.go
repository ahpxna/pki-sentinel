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
