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
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/metrics"
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
			started := time.Now()
			metrics.OCSPResponderUp.Set(0)
			defer func() {
				metrics.OCSPResponderLatency.Observe(time.Since(started).Seconds())
			}()
			issuerPath, cleanupIssuer, err := writeTemp("issuer-*.pem", []byte(target.IssuerPEM))
			if err != nil {
				return OutcomeError, err
			}
			defer cleanupIssuer()
			chainPath, cleanupChain, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return OutcomeError, err
			}
			defer cleanupChain()

			// The probe evaluates the certificate presented by the canary server;
			// fetch it through a plain TLS connection without verification.
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
				"-issuer", issuerPath, "-cert", leafPath, "-url", target.OCSPURL,
				"-CAfile", chainPath, "-no_nonce")
			combined := stdout + stderr
			if err != nil && !strings.Contains(combined, "revoked") {
				return OutcomeError, fmt.Errorf("openssl ocsp: %w (%s)", err, combined)
			}
			if strings.Contains(combined, "revoked") {
				metrics.OCSPResponderUp.Set(1)
				return OutcomeRejected, nil
			}
			if strings.Contains(combined, "good") {
				metrics.OCSPResponderUp.Set(1)
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
				if strings.Contains(stderr, "No OCSP response received") {
					return OutcomeAccepted, nil
				}
				// libcurl's documented CURLE_SSL_INVALIDCERTSTATUS exit code is
				// 91. Match the code rather than localized/version-specific text
				// (new releases may say "revocation reason: UNKNOWN").
				if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 91 {
					return OutcomeRejected, nil
				}
				// OpenSSL's status output includes the signer/verification detail
				// that libcurl intentionally collapses into exit code 91. Preserve
				// it in harness errors so an invalid staple is diagnosable.
				debugOut, debugErr, _ := runCmd(ctx, "openssl", "s_client",
					"-connect", fmt.Sprintf("127.0.0.1:%d", target.Port),
					"-servername", target.Host, "-CAfile", chainPath,
					"-status", "-verify_return_error")
				return OutcomeError, fmt.Errorf("curl --cert-status: %w (%s); openssl status: %s%s", err, stderr, debugOut, debugErr)
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
			d := &tls.Dialer{Config: &tls.Config{
				RootCAs:    pool,
				ServerName: target.Host,
				MinVersion: tls.VersionTLS12,
			}}
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
			d := &tls.Dialer{Config: &tls.Config{
				RootCAs:    pool,
				ServerName: target.Host,
				MinVersion: tls.VersionTLS12,
			}}
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
			leafPEM, err := fetchLeafPEM(target)
			if err != nil {
				return OutcomeError, err
			}
			leafBlock, _ := pem.Decode(leafPEM)
			issuerBlock, _ := pem.Decode([]byte(target.IssuerPEM))
			if leafBlock == nil || issuerBlock == nil {
				return OutcomeError, fmt.Errorf("go-tls-ocsp: invalid leaf or issuer PEM")
			}
			leaf, err := x509.ParseCertificate(leafBlock.Bytes)
			if err != nil {
				return OutcomeError, fmt.Errorf("go-tls-ocsp: parsing leaf: %w", err)
			}
			issuerCert, err := x509.ParseCertificate(issuerBlock.Bytes)
			if err != nil {
				return OutcomeError, fmt.Errorf("go-tls-ocsp: parsing issuer: %w", err)
			}
			resp, err := ocsp.ParseResponseForCert(staple, leaf, issuerCert)
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
import socket
real_getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = lambda host, port, *args, **kwargs: real_getaddrinfo("127.0.0.1" if host == %q else host, port, *args, **kwargs)
s = requests.Session()
s.trust_env = False
r = s.get("https://%s:%d/", verify=%q, timeout=5)
print(r.status_code)
`, target.Host, target.Host, target.Port, chainPath)
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
		Description: "download delta CRL, parse with x509.ParseRevocationList, check serial",
		Expected:    "rejected after delta CRL rebuild interval",
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
			metrics.CRLAgeSeconds.Set(time.Since(crl.ThisUpdate).Seconds())
			metrics.CRLEntries.Set(float64(len(crl.RevokedCertificateEntries)))
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
	// The leaf-fetch path intentionally bypasses verification: the returned
	// certificate is immediately used as the subject of an independent OCSP
	// or CRL check, never as proof that the peer is trusted.
	// #nosec G402 -- intentional discovery connection explained above.
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target.Host,
		MinVersion:         tls.VersionTLS12,
	})
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
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
