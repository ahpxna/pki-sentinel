package issuer

import (
	"bytes"
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestIssueRevoke exercises IssueCanary + Revoke against a live Vault.
// It requires the full stack (`make up && ./scripts/bootstrap.sh`) and is
// skipped automatically if Vault is not reachable, so `go test ./...` stays
// green without infrastructure.
func TestIssueRevoke(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}
	roleID := os.Getenv("PROBE_ROLE_ID")
	secretID := os.Getenv("PROBE_SECRET_ID")
	if roleID == "" || secretID == "" {
		t.Skip("PROBE_ROLE_ID / PROBE_SECRET_ID not set; skipping live-Vault test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := http.Get(vaultAddr + "/v1/sys/health"); err != nil {
		t.Skipf("vault not reachable at %s: %v", vaultAddr, err)
	}

	c, err := Login(ctx, vaultAddr, roleID, secretID)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	cert, err := c.IssueCanary(ctx, "test-cycle.canary.internal")
	if err != nil {
		t.Fatalf("issue canary: %v", err)
	}
	if cert.SerialNumber == "" {
		t.Fatal("expected non-empty serial number")
	}

	tReq, tResp, err := c.Revoke(ctx, cert.SerialNumber)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if tResp.Before(tReq) {
		t.Fatal("expected t_response >= t_request")
	}
}

func TestVerifyIssuedSerialBindsVaultResponseToLeaf(t *testing.T) {
	leaf := big.NewInt(0x1a2b)
	if err := verifyIssuedSerial("1A:2B", leaf); err != nil {
		t.Fatalf("equivalent Vault serial rejected: %v", err)
	}
	for _, serial := range []string{"", "not-hex", "1a2c"} {
		if err := verifyIssuedSerial(serial, leaf); err == nil {
			t.Fatalf("mismatched serial %q was accepted", serial)
		}
	}
}

func TestPEMStrings(t *testing.T) {
	want := []string{"issuer", "root"}
	for name, input := range map[string]interface{}{
		"interface slice": []interface{}{"issuer", "", "root", 42},
		"string slice":    []string{"issuer", "", "root"},
	} {
		t.Run(name, func(t *testing.T) {
			got := pemStrings(input)
			if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
				t.Fatalf("pemStrings(%T) = %v, want %v", input, got, want)
			}
		})
	}
}

func TestFetchCRLDoesNotFollowRedirects(t *testing.T) {
	var redirectTargetHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := (&Client{}).FetchCRL(ctx, redirector.URL); err == nil {
		t.Fatal("redirecting CRL endpoint was accepted")
	}
	if redirectTargetHit.Load() {
		t.Fatal("CRL client followed redirect to an unapproved endpoint")
	}
}

func TestReadStatusBodyRejectsOversizedResponse(t *testing.T) {
	body := bytes.NewReader(make([]byte, maxStatusResponseBytes+1))
	if _, err := readStatusBody(body); err == nil {
		t.Fatal("oversized status response was accepted")
	}
}
