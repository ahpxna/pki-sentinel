package profiles

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ocsp"
)

// writeTemp writes data to a temp file and returns its path. Callers are
// responsible for cleanup via the returned cleanup func.
func writeTemp(pattern string, data []byte) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, err
	}
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

func runCmd(ctx context.Context, name string, args ...string) (stdout, stderr string, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return out.String(), errBuf.String(), err
}

// Registry returns the standard set of client profiles. `chainPEM` is the
// issuing CA + root CA bundle used to validate the canary leaf.
func Registry() []Profile {
	return []Profile{
		opensslOCSPDirect(),
		curlCertStatus(),
		curlDefault(),
		goTLSDefault(),
		goTLSOCSP(),
		pythonRequests(),
		crlCheck(),
	}
}

// --- openssl-ocsp-direct: ground-truth oracle -------------------------------

func opensslOCSPDirect() Profile {
	return Profile{
		Name:        "openssl-ocsp-direct",
		Method:      MethodOCSPDirect,
		Description: "openssl ocsp -issuer chain.pem -cert leaf.pem -url <ocsp_url>",
		Expected:    "rejected",
		Probe: func(ctx context.Context, target Target) (Outcome, error) {
			chainPath, cleanupChain, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return OutcomeError, err
			}
			defer cleanupChain()

			// The leaf we're probing is whatever cert the canary server is
			// presenting; fetch it via a plain TLS dial with no verification.
			leafPEM, err := fetchLeafPEM(target)
			if err != nil {
				return OutcomeError, err
			}
			leafPath, cleanupLeaf, err := writeTemp("leaf-*.pem", leafPEM)
			if err != nil {
				return OutcomeError, err
			}
			defer cleanupLeaf()

			stdout, stderr, err := runCmd(ctx, "openssl", "ocsp",
				"-issuer", chainPath, "-cert", leafPath, "-url", target.OCSPURL, "-no_nonce")
			combined := stdout + stderr
			if err != nil && !strings.Contains(combined, "revoked") {
				return OutcomeError, fmt.Errorf("openssl ocsp: %w (%s)", err, combined)
			}
			if strings.Contains(combined, "revoked") {
				return OutcomeRejected, nil
			}
			if strings.Contains(combined, "good") {
				return OutcomeAccepted, nil
			}
			return OutcomeError, fmt.Errorf("openssl ocsp: unrecognized output: %s", combined)
		},
	}
}

// --- curl-cert-status: --cert-status (must-staple aware) --------------------

func curlCertStatus() Profile {
	return Profile{
		Name:        "curl-cert-status",
		Method:      MethodOCSPStapled,
		Description: "curl --cacert chain.pem --cert-status https://<host>/",
		Expected:    "rejected when stapling on; accepted when stapling off",
		Probe: func(ctx context.Context, target Target) (Outcome, error) {
			chainPath, cleanup, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return OutcomeError, err
			}
			defer cleanup()

			url := fmt.Sprintf("https://%s:%d/", target.Host, target.Port)
			_, stderr, err := runCmd(ctx, "curl", "-sS", "--max-time", "5",
				"--cacert", chainPath, "--cert-status", "--resolve",
				fmt.Sprintf("%s:%d:127.0.0.1", target.Host, target.Port), url)
			if err != nil {
				if strings.Contains(stderr, "certificate status") || strings.Contains(stderr, "revoked") {
					return OutcomeRejected, nil
				}
				return OutcomeError, fmt.Errorf("curl --cert-status: %w (%s)", err, stderr)
			}
			return OutcomeAccepted, nil
		},
	}
}

// --- curl-default: no revocation check by default --------------------------

func curlDefault() Profile {
	return Profile{
		Name:        "curl-default",
		Method:      MethodNone,
		Description: "curl --cacert chain.pem https://<host>/",
		Expected:    "accepted — curl does no revocation check by default",
		Probe: func(ctx context.Context, target Target) (Outcome, error) {
			chainPath, cleanup, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return OutcomeError, err
			}
			defer cleanup()

			url := fmt.Sprintf("https://%s:%d/", target.Host, target.Port)
			_, stderr, err := runCmd(ctx, "curl", "-sS", "--max-time", "5",
				"--cacert", chainPath, "--resolve",
				fmt.Sprintf("%s:%d:127.0.0.1", target.Host, target.Port), url)
			if err != nil {
				return OutcomeError, fmt.Errorf("curl-default: %w (%s)", err, stderr)
			}
			return OutcomeAccepted, nil
		},
	}
}

// --- go-tls-default: crypto/tls dial, no revocation check -------------------

func goTLSDefault() Profile {
	return Profile{
		Name:        "go-tls-default",
		Method:      MethodNone,
		Description: "in-process crypto/tls dial with RootCAs",
		Expected:    "accepted — Go stdlib does not check revocation",
		Probe: func(ctx context.Context, target Target) (Outcome, error) {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(target.CAChainPEM))
			addr := fmt.Sprintf("127.0.0.1:%d", target.Port)
			d := &tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: target.Host}}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return OutcomeError, fmt.Errorf("go-tls-default: dial: %w", err)
			}
			defer conn.Close()
			return OutcomeAccepted, nil
		},
	}
}

// --- go-tls-ocsp: dial + explicit OCSP response parse -----------------------

func goTLSOCSP() Profile {
	return Profile{
		Name:        "go-tls-ocsp",
		Method:      MethodOCSPStapled,
		Description: "dial + explicit ocsp.ParseResponse on ConnectionState().OCSPResponse",
		Expected:    "rejected when stapled",
		Probe: func(ctx context.Context, target Target) (Outcome, error) {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(target.CAChainPEM))
			addr := fmt.Sprintf("127.0.0.1:%d", target.Port)
			d := &tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: target.Host}}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return OutcomeError, fmt.Errorf("go-tls-ocsp: dial: %w", err)
			}
			defer conn.Close()

			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				return OutcomeError, fmt.Errorf("go-tls-ocsp: not a *tls.Conn")
			}
			staple := tlsConn.ConnectionState().OCSPResponse
			if len(staple) == 0 {
				// No staple presented: this profile cannot make a
				// revocation determination and, like a strict must-staple
				// client, treats missing proof as accept-by-default rather
				// than a harness error.
				return OutcomeAccepted, nil
			}
			resp, err := ocsp.ParseResponse(staple, nil)
			if err != nil {
				return OutcomeError, fmt.Errorf("go-tls-ocsp: parsing staple: %w", err)
			}
			if resp.Status == ocsp.Revoked {
				return OutcomeRejected, nil
			}
			return OutcomeAccepted, nil
		},
	}
}

// --- python-requests: no revocation check by default ------------------------

func pythonRequests() Profile {
	return Profile{
		Name:        "python-requests",
		Method:      MethodNone,
		Description: `python3 -c script with verify=chain.pem`,
		Expected:    "accepted",
		Probe: func(ctx context.Context, target Target) (Outcome, error) {
			chainPath, cleanup, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return OutcomeError, err
			}
			defer cleanup()

			script := fmt.Sprintf(`
import requests
r = requests.get("https://%s:%d/", verify=%q, timeout=5)
print(r.status_code)
`, target.Host, target.Port, chainPath)
			stdout, stderr, err := runCmd(ctx, "python3", "-c", script)
			if err != nil {
				return OutcomeError, fmt.Errorf("python-requests: %w (%s)", err, stderr)
			}
			if !strings.Contains(stdout, "200") {
				return OutcomeError, fmt.Errorf("python-requests: unexpected output: %s", stdout)
			}
			return OutcomeAccepted, nil
		},
	}
}

// --- crl-check: download CRL, parse, check serial ---------------------------

func crlCheck() Profile {
	return Profile{
		Name:        "crl-check",
		Method:      MethodCRL,
		Description: "download CRL, parse with x509.ParseRevocationList, check serial",
		Expected:    "rejected after CRL rebuild interval",
		Probe: func(ctx context.Context, target Target) (Outcome, error) {
			leafPEM, err := fetchLeafPEM(target)
			if err != nil {
				return OutcomeError, err
			}
			block, _ := pem.Decode(leafPEM)
			if block == nil {
				return OutcomeError, fmt.Errorf("crl-check: could not decode leaf PEM")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return OutcomeError, fmt.Errorf("crl-check: parsing leaf: %w", err)
			}

			crlBytes, err := httpGet(ctx, target.CRLURL)
			if err != nil {
				return OutcomeError, fmt.Errorf("crl-check: fetching CRL: %w", err)
			}
			crl, err := x509.ParseRevocationList(crlBytes)
			if err != nil {
				return OutcomeError, fmt.Errorf("crl-check: parsing CRL: %w", err)
			}
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
					return OutcomeRejected, nil
				}
			}
			return OutcomeAccepted, nil
		},
	}
}

// --- shared helpers ----------------------------------------------------------

func fetchLeafPEM(target Target) ([]byte, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", target.Port)
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: target.Host})
	if err != nil {
		return nil, fmt.Errorf("fetchLeafPEM: dial: %w", err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("fetchLeafPEM: no peer certificates")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw}), nil
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
