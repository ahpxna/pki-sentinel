package issuer

import (
	"context"
	"net/http"
	"os"
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
