package profiles

import "testing"

func TestRegistryHasSevenBaselineProfiles(t *testing.T) {
	reg := Registry()
	if len(reg) != 7 {
		t.Fatalf("expected 7 baseline profiles, got %d", len(reg))
	}

	wantMethods := map[string]CheckMethod{
		"openssl-ocsp-direct": MethodOCSPDirect,
		"curl-cert-status":    MethodOCSPStapled,
		"curl-default":        MethodNone,
		"go-tls-default":      MethodNone,
		"go-tls-ocsp":         MethodOCSPStapled,
		"python-requests":     MethodNone,
		"crl-check":           MethodCRL,
	}

	seen := map[string]bool{}
	for _, p := range reg {
		if p.Probe == nil {
			t.Errorf("profile %s has a nil Probe func", p.Name)
		}
		wantMethod, ok := wantMethods[p.Name]
		if !ok {
			t.Errorf("unexpected profile name %s", p.Name)
			continue
		}
		if p.Method != wantMethod {
			t.Errorf("profile %s: expected method %s, got %s", p.Name, wantMethod, p.Method)
		}
		seen[p.Name] = true
	}
	for name := range wantMethods {
		if !seen[name] {
			t.Errorf("missing expected profile %s", name)
		}
	}
}
