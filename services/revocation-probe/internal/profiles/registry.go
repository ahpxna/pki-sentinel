package profiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
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

func observe(decision Decision, reason Reason) Observation {
	return Observation{Decision: decision, Reason: reason}
}

func targetConnectHost(target Target) string {
	if target.ConnectHost != "" {
		return target.ConnectHost
	}
	return "127.0.0.1"
}

func inProcessObservation(client string, decision Decision, reason Reason) Observation {
	version, backend := clientFingerprint("go")
	return Observation{
		Decision: decision,
		Reason:   reason,
		Evidence: CommandEvidence{Client: client, ClientVersion: version, TLSBackend: backend},
	}
}

func commandEvidence(client, stdout, stderr string, err error) CommandEvidence {
	stdoutHash := sha256.Sum256([]byte(stdout))
	stderrHash := sha256.Sum256([]byte(stderr))
	evidence := CommandEvidence{
		Client:       client,
		StdoutSHA256: hex.EncodeToString(stdoutHash[:]),
		StderrSHA256: hex.EncodeToString(stderrHash[:]),
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		code := exitErr.ExitCode()
		evidence.ExitCode = &code
	} else if err == nil {
		code := 0
		evidence.ExitCode = &code
	}
	version, backend := clientFingerprint(client)
	evidence.ClientVersion = version
	evidence.TLSBackend = backend
	return evidence
}

var fingerprintCache sync.Map

func runFingerprintCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stdout, _, err := runCmd(ctx, name, args...)
	return stdout, err
}

func clientFingerprint(client string) (string, string) {
	if value, ok := fingerprintCache.Load(client); ok {
		parts := value.([2]string)
		return parts[0], parts[1]
	}
	var version, backend string
	switch client {
	case "curl":
		stdout, err := runFingerprintCommand("curl", "--version")
		if err == nil {
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			if len(lines) > 0 {
				fields := strings.Fields(lines[0])
				if len(fields) > 1 {
					version = fields[1]
				}
				for _, field := range fields {
					if strings.Contains(field, "/") && (strings.Contains(strings.ToLower(field), "ssl") || strings.Contains(strings.ToLower(field), "gnutls")) {
						backend = field
						break
					}
				}
			}
		}
	case "openssl":
		stdout, err := runFingerprintCommand("openssl", "version")
		if err == nil {
			version = strings.TrimSpace(stdout)
			backend = version
		}
	case "python-requests":
		stdout, err := runFingerprintCommand("python3", "-c", "import requests,ssl;print(requests.__version__);print(ssl.OPENSSL_VERSION)")
		if err == nil {
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			if len(lines) > 0 {
				version = lines[0]
			}
			if len(lines) > 1 {
				backend = lines[1]
			}
		}
	case "go":
		version = "go" + strings.TrimPrefix(strings.TrimSpace(runtimeVersion()), "go")
		backend = "crypto/tls"
	}
	result := [2]string{version, backend}
	fingerprintCache.Store(client, result)
	return result[0], result[1]
}

var runtimeVersion = runtime.Version

func allScenarioExpectations(before Decision, beforeReason Reason, after Decision, afterReason Reason) map[Scenario]Expectation {
	return map[Scenario]Expectation{
		ScenarioRevokedStaple:    {Before: before, BeforeReasons: []Reason{beforeReason}, After: after, AfterReasons: []Reason{afterReason}},
		ScenarioMissingStaple:    {Before: before, BeforeReasons: []Reason{beforeReason}, After: after, AfterReasons: []Reason{afterReason}},
		ScenarioCachedGoodStaple: {Before: before, BeforeReasons: []Reason{beforeReason}, After: after, AfterReasons: []Reason{afterReason}},
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

func classifyCurlCertStatus(stderr string, code int, failed bool) (Decision, Reason) {
	if !failed {
		return DecisionAccept, ReasonStatusGood
	}
	if code == 91 {
		lower := strings.ToLower(stderr)
		switch {
		case strings.Contains(lower, "no ocsp response"):
			return DecisionReject, ReasonMissingStatus
		case strings.Contains(lower, "revoked"):
			return DecisionReject, ReasonRevoked
		default:
			return DecisionReject, ReasonInvalidStatus
		}
	}
	if code == 28 || strings.Contains(strings.ToLower(stderr), "timed out") {
		return DecisionInconclusive, ReasonNetworkFailure
	}
	return DecisionHarnessError, ReasonHarnessFailure
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
		Name:         "openssl-ocsp-direct",
		Role:         RoleStatusOracle,
		Method:       MethodOCSPDirect,
		Description:  "openssl ocsp -issuer chain.pem -cert leaf.pem -url <ocsp_url>",
		Expectations: allScenarioExpectations(DecisionAccept, ReasonStatusGood, DecisionReject, ReasonRevoked),
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			started := time.Now()
			metrics.OCSPResponderUp.Set(0)
			defer func() {
				metrics.OCSPResponderLatency.Observe(time.Since(started).Seconds())
			}()
			issuerPath, cleanupIssuer, err := writeTemp("issuer-*.pem", []byte(target.IssuerPEM))
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			defer cleanupIssuer()
			chainPath, cleanupChain, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			defer cleanupChain()

			// The probe evaluates the certificate presented by the canary server;
			// fetch it through a plain TLS connection without verification.
			leafPEM, err := fetchLeafPEM(ctx, target)
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			leafPath, cleanupLeaf, err := writeTemp("leaf-*.pem", leafPEM)
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			defer cleanupLeaf()

			stdout, stderr, err := runCmd(ctx, "openssl", "ocsp",
				"-issuer", issuerPath, "-cert", leafPath, "-url", target.OCSPURL,
				"-CAfile", chainPath, "-no_nonce")
			combined := stdout + stderr
			if err != nil && !strings.Contains(combined, "revoked") {
				decision := DecisionHarnessError
				reason := ReasonHarnessFailure
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
					decision = DecisionInconclusive
					reason = ReasonNetworkFailure
				}
				observation := observe(decision, reason)
				observation.Evidence = commandEvidence("openssl", stdout, stderr, err)
				if decision == DecisionHarnessError {
					return observation, fmt.Errorf("openssl ocsp: %w", err)
				}
				return observation, nil
			}
			if strings.Contains(combined, "revoked") {
				metrics.OCSPResponderUp.Set(1)
				observation := observe(DecisionReject, ReasonRevoked)
				observation.Evidence = commandEvidence("openssl", stdout, stderr, err)
				return observation, nil
			}
			if strings.Contains(combined, "good") {
				metrics.OCSPResponderUp.Set(1)
				observation := observe(DecisionAccept, ReasonStatusGood)
				observation.Evidence = commandEvidence("openssl", stdout, stderr, err)
				return observation, nil
			}
			observation := observe(DecisionHarnessError, ReasonHarnessFailure)
			observation.Evidence = commandEvidence("openssl", stdout, stderr, err)
			return observation, fmt.Errorf("openssl ocsp: unrecognized output: %s", combined)
		},
	}
}

// --- curl-cert-status: --cert-status (must-staple aware) --------------------

func curlCertStatus() Profile {
	return Profile{
		Name:        "curl-cert-status",
		Role:        RoleClientExecutor,
		Method:      MethodOCSPStapled,
		Description: "curl --cacert chain.pem --cert-status https://<host>/",
		Expectations: map[Scenario]Expectation{
			ScenarioRevokedStaple:    {Before: DecisionAccept, BeforeReasons: []Reason{ReasonStatusGood}, After: DecisionReject, AfterReasons: []Reason{ReasonRevoked, ReasonInvalidStatus}},
			ScenarioMissingStaple:    {Before: DecisionReject, BeforeReasons: []Reason{ReasonMissingStatus}, After: DecisionReject, AfterReasons: []Reason{ReasonMissingStatus}},
			ScenarioCachedGoodStaple: {Before: DecisionAccept, BeforeReasons: []Reason{ReasonStatusGood}, After: DecisionAccept, AfterReasons: []Reason{ReasonStatusGood}},
		},
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			chainPath, cleanup, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			defer cleanup()

			url := fmt.Sprintf("https://%s:%d/", target.Host, target.Port)
			stdout, stderr, err := runCmd(ctx, "curl", "-sS", "--max-time", "5",
				"--cacert", chainPath, "--cert-status", "--connect-to",
				fmt.Sprintf("%s:%d:%s:%d", target.Host, target.Port, targetConnectHost(target), target.Port), url)
			decision, reason := classifyCurlCertStatus(stderr, exitCode(err), err != nil)
			observation := observe(decision, reason)
			observation.Evidence = commandEvidence("curl", stdout, stderr, err)
			if decision == DecisionHarnessError {
				return observation, fmt.Errorf("curl --cert-status: %w (%s)", err, stderr)
			}
			return observation, nil
		},
	}
}

// --- curl-default: no revocation check by default --------------------------

func curlDefault() Profile {
	return Profile{
		Name:         "curl-default",
		Role:         RoleClientExecutor,
		Method:       MethodNone,
		Description:  "curl --cacert chain.pem https://<host>/",
		Expectations: allScenarioExpectations(DecisionAccept, ReasonNoRevocationCheck, DecisionAccept, ReasonNoRevocationCheck),
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			chainPath, cleanup, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			defer cleanup()

			url := fmt.Sprintf("https://%s:%d/", target.Host, target.Port)
			stdout, stderr, err := runCmd(ctx, "curl", "-sS", "--max-time", "5",
				"--cacert", chainPath, "--connect-to",
				fmt.Sprintf("%s:%d:%s:%d", target.Host, target.Port, targetConnectHost(target), target.Port), url)
			if err != nil {
				decision := DecisionInconclusive
				reason := ReasonTLSFailure
				if exitCode(err) == 28 {
					reason = ReasonNetworkFailure
				}
				observation := observe(decision, reason)
				observation.Evidence = commandEvidence("curl", stdout, stderr, err)
				return observation, nil
			}
			observation := observe(DecisionAccept, ReasonNoRevocationCheck)
			observation.Evidence = commandEvidence("curl", stdout, stderr, err)
			return observation, nil
		},
	}
}

// --- go-tls-default: crypto/tls dial, no revocation check -------------------

func goTLSDefault() Profile {
	return Profile{
		Name:         "go-tls-default",
		Role:         RoleClientExecutor,
		Method:       MethodNone,
		Description:  "in-process crypto/tls dial with RootCAs",
		Expectations: allScenarioExpectations(DecisionAccept, ReasonNoRevocationCheck, DecisionAccept, ReasonNoRevocationCheck),
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(target.CAChainPEM))
			addr := fmt.Sprintf("%s:%d", targetConnectHost(target), target.Port)
			d := &tls.Dialer{Config: &tls.Config{
				RootCAs:    pool,
				ServerName: target.Host,
				MinVersion: tls.VersionTLS12,
			}}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return inProcessObservation("go-default-tls", DecisionInconclusive, ReasonTLSFailure), nil
			}
			defer conn.Close()
			return inProcessObservation("go-default-tls", DecisionAccept, ReasonNoRevocationCheck), nil
		},
	}
}

// --- go-hardfail-ocsp: dial + explicit OCSP response validation -------------

func goTLSOCSP() Profile {
	return Profile{
		Name:        "go-hardfail-ocsp",
		Role:        RoleClientExecutor,
		Method:      MethodOCSPStapled,
		Description: "custom hard-fail validator over crypto/tls OCSPResponse",
		Expectations: map[Scenario]Expectation{
			ScenarioRevokedStaple:    {Before: DecisionAccept, BeforeReasons: []Reason{ReasonStatusGood}, After: DecisionReject, AfterReasons: []Reason{ReasonRevoked}},
			ScenarioMissingStaple:    {Before: DecisionReject, BeforeReasons: []Reason{ReasonMissingStatus}, After: DecisionReject, AfterReasons: []Reason{ReasonMissingStatus}},
			ScenarioCachedGoodStaple: {Before: DecisionAccept, BeforeReasons: []Reason{ReasonStatusGood}, After: DecisionAccept, AfterReasons: []Reason{ReasonStatusGood}},
		},
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(target.CAChainPEM))
			addr := fmt.Sprintf("%s:%d", targetConnectHost(target), target.Port)
			d := &tls.Dialer{Config: &tls.Config{
				RootCAs:    pool,
				ServerName: target.Host,
				MinVersion: tls.VersionTLS12,
			}}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return inProcessObservation("go-hardfail-ocsp", DecisionInconclusive, ReasonTLSFailure), nil
			}
			defer conn.Close()

			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("go-hardfail-ocsp: not a *tls.Conn")
			}
			state := tlsConn.ConnectionState()
			staple := state.OCSPResponse
			if len(staple) == 0 {
				return inProcessObservation("go-hardfail-ocsp", DecisionReject, ReasonMissingStatus), nil
			}
			if len(state.PeerCertificates) == 0 {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("go-hardfail-ocsp: TLS peer sent no certificate")
			}
			issuerBlock, _ := pem.Decode([]byte(target.IssuerPEM))
			if issuerBlock == nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("go-hardfail-ocsp: invalid issuer PEM")
			}
			leaf := state.PeerCertificates[0]
			issuerCert, err := x509.ParseCertificate(issuerBlock.Bytes)
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("go-hardfail-ocsp: parsing issuer: %w", err)
			}
			resp, err := ocsp.ParseResponseForCert(staple, leaf, issuerCert)
			if err != nil {
				return inProcessObservation("go-hardfail-ocsp", DecisionReject, ReasonInvalidStatus), nil
			}
			if !resp.NextUpdate.IsZero() && time.Now().After(resp.NextUpdate) {
				return inProcessObservation("go-hardfail-ocsp", DecisionReject, ReasonStaleStatus), nil
			}
			if resp.Status == ocsp.Revoked {
				return inProcessObservation("go-hardfail-ocsp", DecisionReject, ReasonRevoked), nil
			}
			if resp.Status == ocsp.Unknown {
				return inProcessObservation("go-hardfail-ocsp", DecisionReject, ReasonUnknownStatus), nil
			}
			return inProcessObservation("go-hardfail-ocsp", DecisionAccept, ReasonStatusGood), nil
		},
	}
}

// --- python-requests: no revocation check by default ------------------------

func pythonRequests() Profile {
	return Profile{
		Name:         "python-requests",
		Role:         RoleClientExecutor,
		Method:       MethodNone,
		Description:  `python3 -c script with verify=chain.pem`,
		Expectations: allScenarioExpectations(DecisionAccept, ReasonNoRevocationCheck, DecisionAccept, ReasonNoRevocationCheck),
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			chainPath, cleanup, err := writeTemp("chain-*.pem", []byte(target.CAChainPEM))
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			defer cleanup()

			script := fmt.Sprintf(`
import requests
import socket
real_getaddrinfo = socket.getaddrinfo
socket.getaddrinfo = lambda host, port, *args, **kwargs: real_getaddrinfo(%q if host == %q else host, port, *args, **kwargs)
s = requests.Session()
s.trust_env = False
r = s.get("https://%s:%d/", verify=%q, timeout=5)
print(r.status_code)
`, targetConnectHost(target), target.Host, target.Host, target.Port, chainPath)
			stdout, stderr, err := runCmd(ctx, "python3", "-c", script)
			if err != nil {
				observation := observe(DecisionInconclusive, ReasonTLSFailure)
				observation.Evidence = commandEvidence("python-requests", stdout, stderr, err)
				return observation, nil
			}
			if !strings.Contains(stdout, "200") {
				observation := observe(DecisionHarnessError, ReasonHarnessFailure)
				observation.Evidence = commandEvidence("python-requests", stdout, stderr, err)
				return observation, fmt.Errorf("python-requests: unexpected output: %s", stdout)
			}
			observation := observe(DecisionAccept, ReasonNoRevocationCheck)
			observation.Evidence = commandEvidence("python-requests", stdout, stderr, err)
			return observation, nil
		},
	}
}

// --- crl-check: download CRL, parse, check serial ---------------------------

func crlCheck() Profile {
	return Profile{
		Name:         "crl-check",
		Role:         RoleStatusOracle,
		Method:       MethodCRL,
		Description:  "download delta CRL, parse with x509.ParseRevocationList, check serial",
		Expectations: allScenarioExpectations(DecisionAccept, ReasonStatusGood, DecisionReject, ReasonRevoked),
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			leafPEM, err := fetchLeafPEM(ctx, target)
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			block, _ := pem.Decode(leafPEM)
			if block == nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("crl-check: could not decode leaf PEM")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("crl-check: parsing leaf: %w", err)
			}

			crlBytes, err := httpGet(ctx, target.CRLURL)
			if err != nil {
				return inProcessObservation("go-crl-oracle", DecisionInconclusive, ReasonNetworkFailure), nil
			}
			crl, err := x509.ParseRevocationList(crlBytes)
			if err != nil {
				return inProcessObservation("go-crl-oracle", DecisionReject, ReasonInvalidStatus), nil
			}
			metrics.CRLAgeSeconds.Set(time.Since(crl.ThisUpdate).Seconds())
			metrics.CRLEntries.Set(float64(len(crl.RevokedCertificateEntries)))
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
					return inProcessObservation("go-crl-oracle", DecisionReject, ReasonRevoked), nil
				}
			}
			return inProcessObservation("go-crl-oracle", DecisionAccept, ReasonStatusGood), nil
		},
	}
}

// --- shared helpers ----------------------------------------------------------

func fetchLeafPEM(ctx context.Context, target Target) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", targetConnectHost(target), target.Port)
	// The leaf-fetch path intentionally bypasses verification: the returned
	// certificate is immediately used as the subject of an independent OCSP
	// or CRL check, never as proof that the peer is trusted.
	// #nosec G402 -- intentional discovery connection explained above.
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target.Host,
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fetchLeafPEM: dial: %w", err)
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("fetchLeafPEM: dial did not return a TLS connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
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
