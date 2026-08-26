package profiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

func withCommandEvidence(observation Observation, client, stdout, stderr string, err error) Observation {
	observation.Evidence = commandEvidence(client, stdout, stderr, err)
	observation.Evidence.RawArtifacts = []RawArtifact{
		{Name: "stdout.txt", MediaType: "text/plain; charset=utf-8", Data: stdout},
		{Name: "stderr.txt", MediaType: "text/plain; charset=utf-8", Data: stderr},
	}
	return observation
}

func binaryArtifact(name, mediaType string, data []byte) RawArtifact {
	return RawArtifact{Name: name, MediaType: mediaType, Encoding: "base64", Data: base64.StdEncoding.EncodeToString(data)}
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
		Name:        "openssl-ocsp-direct",
		Role:        RoleStatusOracle,
		Method:      MethodOCSPDirect,
		Description: "OpenSSL OCSP transport with Sentinel signature, subject, and freshness classification",
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			started := time.Now()
			metrics.OCSPResponderUp.Set(0)
			defer func() { metrics.OCSPResponderLatency.Observe(time.Since(started).Seconds()) }()

			leaf, presentedHash, err := fetchPresentedLeaf(ctx, target)
			if err != nil {
				observation := observe(DecisionHarnessError, ReasonHarnessFailure)
				observation.Evidence.PresentedLeafSHA256 = presentedHash
				return observation, err
			}
			issuerBlock, _ := pem.Decode([]byte(target.IssuerPEM))
			if issuerBlock == nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("openssl-ocsp-direct: invalid issuer PEM")
			}
			issuerCert, err := x509.ParseCertificate(issuerBlock.Bytes)
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("openssl-ocsp-direct: parse issuer: %w", err)
			}
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
			leafPath, cleanupLeaf, err := writeTemp("leaf-*.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), err
			}
			defer cleanupLeaf()
			responseFile, err := os.CreateTemp("", "ocsp-response-*.der")
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("create OCSP response artifact: %w", err)
			}
			responsePath := responseFile.Name()
			if err := responseFile.Close(); err != nil {
				os.Remove(responsePath)
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("close OCSP response artifact: %w", err)
			}
			defer os.Remove(responsePath)

			stdout, stderr, cmdErr := runCmd(ctx, "openssl", "ocsp",
				"-issuer", issuerPath, "-cert", leafPath, "-url", target.OCSPURL,
				"-CAfile", chainPath, "-no_nonce", "-respout", responsePath)
			responseDER, responseReadErr := os.ReadFile(responsePath)
			withEvidence := func(observation Observation) Observation {
				observation = withCommandEvidence(observation, "openssl", stdout, stderr, cmdErr)
				observation.Evidence.PresentedLeafSHA256 = presentedHash
				if responseReadErr == nil && len(responseDER) > 0 {
					observation = withBinaryEvidence(observation, "ocsp-response.der", "application/ocsp-response", responseDER)
				}
				return observation
			}

			if len(responseDER) == 0 {
				if ctx.Err() != nil || looksLikeNetworkFailure(stderr) {
					return withEvidence(observe(DecisionInconclusive, ReasonNetworkFailure)), nil
				}
				var execErr *exec.Error
				if errors.As(cmdErr, &execErr) || responseReadErr != nil {
					observation := withEvidence(observe(DecisionHarnessError, ReasonHarnessFailure))
					return observation, fmt.Errorf("openssl ocsp transport failed without a response: command=%v read=%v", cmdErr, responseReadErr)
				}
				return withEvidence(observe(DecisionReject, ReasonInvalidStatus)), nil
			}

			resp, parseErr := ocsp.ParseResponseForCert(responseDER, leaf, issuerCert)
			if parseErr != nil {
				return withEvidence(observe(DecisionReject, ReasonInvalidStatus)), nil
			}
			if reason := checkOCSPFreshness(resp, time.Now(), target.StatusFreshness, target.OCSPFreshness); reason != "" {
				metrics.OCSPResponderUp.Set(1)
				return withEvidence(observe(DecisionReject, reason)), nil
			}
			if resp.Status == ocsp.Revoked {
				if reason := checkRevocationTime(resp.RevokedAt, leaf.NotBefore, time.Now(), target.StatusFreshness); reason != "" {
					metrics.OCSPResponderUp.Set(1)
					return withEvidence(observe(DecisionReject, reason)), nil
				}
			}
			metrics.OCSPResponderUp.Set(1)
			switch resp.Status {
			case ocsp.Revoked:
				return withEvidence(observe(DecisionReject, ReasonRevoked)), nil
			case ocsp.Good:
				return withEvidence(observe(DecisionAccept, ReasonStatusGood)), nil
			case ocsp.Unknown:
				return withEvidence(observe(DecisionReject, ReasonUnknownStatus)), nil
			default:
				return withEvidence(observe(DecisionReject, ReasonInvalidStatus)), nil
			}
		},
	}
}

func looksLikeNetworkFailure(stderr string) bool {
	lower := strings.ToLower(stderr)
	for _, marker := range []string{"connection refused", "connection timed out", "timed out", "no route to host", "temporary failure", "name or service not known", "getaddrinfo", "connect error"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// --- curl-cert-status: --cert-status (must-staple aware) --------------------

func curlCertStatus() Profile {
	return Profile{
		Name:        "curl-cert-status",
		Role:        RoleClientExecutor,
		Method:      MethodOCSPStapled,
		Description: "curl --cacert chain.pem --cert-status https://<host>/",
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
			observation = withCommandEvidence(observation, "curl", stdout, stderr, err)
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
		Name:        "curl-default",
		Role:        RoleClientExecutor,
		Method:      MethodNone,
		Description: "curl --cacert chain.pem https://<host>/",
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
				observation = withCommandEvidence(observation, "curl", stdout, stderr, err)
				return observation, nil
			}
			observation := observe(DecisionAccept, ReasonNoRevocationCheck)
			observation = withCommandEvidence(observation, "curl", stdout, stderr, err)
			return observation, nil
		},
	}
}

// --- go-tls-default: crypto/tls dial, no revocation check -------------------

func goTLSDefault() Profile {
	return Profile{
		Name:        "go-tls-default",
		Role:        RoleClientExecutor,
		Method:      MethodNone,
		Description: "in-process crypto/tls dial with RootCAs",
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
				return withBinaryEvidence(inProcessObservation("go-hardfail-ocsp", DecisionReject, ReasonInvalidStatus), "stapled-ocsp.der", "application/ocsp-response", staple), nil
			}
			if reason := checkOCSPFreshness(resp, time.Now(), target.StatusFreshness, target.OCSPFreshness); reason != "" {
				return withBinaryEvidence(inProcessObservation("go-hardfail-ocsp", DecisionReject, reason), "stapled-ocsp.der", "application/ocsp-response", staple), nil
			}
			if resp.Status == ocsp.Revoked {
				if reason := checkRevocationTime(resp.RevokedAt, leaf.NotBefore, time.Now(), target.StatusFreshness); reason != "" {
					return withBinaryEvidence(inProcessObservation("go-hardfail-ocsp", DecisionReject, reason), "stapled-ocsp.der", "application/ocsp-response", staple), nil
				}
				return withBinaryEvidence(inProcessObservation("go-hardfail-ocsp", DecisionReject, ReasonRevoked), "stapled-ocsp.der", "application/ocsp-response", staple), nil
			}
			if resp.Status == ocsp.Unknown {
				return withBinaryEvidence(inProcessObservation("go-hardfail-ocsp", DecisionReject, ReasonUnknownStatus), "stapled-ocsp.der", "application/ocsp-response", staple), nil
			}
			return withBinaryEvidence(inProcessObservation("go-hardfail-ocsp", DecisionAccept, ReasonStatusGood), "stapled-ocsp.der", "application/ocsp-response", staple), nil
		},
	}
}

// --- python-requests: no revocation check by default ------------------------

func pythonRequests() Profile {
	return Profile{
		Name:        "python-requests",
		Role:        RoleClientExecutor,
		Method:      MethodNone,
		Description: `python3 -c script with verify=chain.pem`,
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
				observation = withCommandEvidence(observation, "python-requests", stdout, stderr, err)
				return observation, nil
			}
			if !strings.Contains(stdout, "200") {
				observation := observe(DecisionHarnessError, ReasonHarnessFailure)
				observation = withCommandEvidence(observation, "python-requests", stdout, stderr, err)
				return observation, fmt.Errorf("python-requests: unexpected output: %s", stdout)
			}
			observation := observe(DecisionAccept, ReasonNoRevocationCheck)
			observation = withCommandEvidence(observation, "python-requests", stdout, stderr, err)
			return observation, nil
		},
	}
}

// --- crl-check: download CRL, parse, check serial ---------------------------

func crlCheck() Profile {
	return Profile{
		Name:        "crl-check",
		Role:        RoleStatusOracle,
		Method:      MethodCRL,
		Description: "download full CRL, verify issuer signature/freshness, and check the exact issued canary serial",
		Probe: func(ctx context.Context, target Target) (Observation, error) {
			leaf, presentedHash, err := fetchPresentedLeaf(ctx, target)
			if err != nil {
				observation := observe(DecisionHarnessError, ReasonHarnessFailure)
				observation.Evidence.PresentedLeafSHA256 = presentedHash
				return observation, err
			}
			withLeaf := func(observation Observation) Observation {
				observation.Evidence.PresentedLeafSHA256 = presentedHash
				return observation
			}
			crlBytes, err := httpGet(ctx, target.CRLURL)
			if err != nil {
				return withLeaf(inProcessObservation("go-crl-oracle", DecisionInconclusive, ReasonNetworkFailure)), nil
			}
			withCRL := func(observation Observation) Observation {
				return withBinaryEvidence(withLeaf(observation), "crl.der", "application/pkix-crl", crlBytes)
			}
			crl, err := x509.ParseRevocationList(crlBytes)
			if err != nil {
				return withCRL(inProcessObservation("go-crl-oracle", DecisionReject, ReasonInvalidStatus)), nil
			}
			issuerBlock, _ := pem.Decode([]byte(target.IssuerPEM))
			if issuerBlock == nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("crl-check: invalid issuer PEM")
			}
			issuerCert, err := x509.ParseCertificate(issuerBlock.Bytes)
			if err != nil {
				return observe(DecisionHarnessError, ReasonHarnessFailure), fmt.Errorf("crl-check: parsing issuer: %w", err)
			}
			if err := crl.CheckSignatureFrom(issuerCert); err != nil {
				return withCRL(inProcessObservation("go-crl-oracle", DecisionReject, ReasonInvalidStatus)), nil
			}
			now := time.Now()
			if reason := checkCRLFreshness(crl, now, target.StatusFreshness, target.CRLFreshness); reason != "" {
				return withCRL(inProcessObservation("go-crl-oracle", DecisionReject, reason)), nil
			}
			metrics.CRLAgeSeconds.Set(now.Sub(crl.ThisUpdate).Seconds())
			metrics.CRLEntries.Set(float64(len(crl.RevokedCertificateEntries)))
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
					if reason := checkRevocationTime(entry.RevocationTime, leaf.NotBefore, now, target.StatusFreshness); reason != "" {
						return withCRL(inProcessObservation("go-crl-oracle", DecisionReject, reason)), nil
					}
					return withCRL(inProcessObservation("go-crl-oracle", DecisionReject, ReasonRevoked)), nil
				}
			}
			return withCRL(inProcessObservation("go-crl-oracle", DecisionAccept, ReasonStatusGood)), nil
		},
	}
}

func withBinaryEvidence(observation Observation, name, mediaType string, contents []byte) Observation {
	observation.Evidence.RawArtifacts = append(observation.Evidence.RawArtifacts, binaryArtifact(name, mediaType, contents))
	return observation
}

func checkOCSPFreshness(response *ocsp.Response, now time.Time, configuredStatus StatusFreshnessPolicy, configuredOCSP OCSPFreshnessPolicy) Reason {
	status := configuredStatus.WithDefaults()
	policy := configuredOCSP.WithDefaults()
	if response.ThisUpdate.After(now.Add(status.MaxClockSkew)) || response.ProducedAt.After(now.Add(status.MaxClockSkew)) {
		return ReasonFutureStatus
	}
	if response.NextUpdate.IsZero() {
		if policy.RequireNextUpdate {
			return ReasonMissingFreshness
		}
		if now.Sub(response.ThisUpdate) > policy.MaxAgeWithoutNextUpdate {
			return ReasonStaleStatus
		}
		return ""
	}
	if now.After(response.NextUpdate) {
		return ReasonStaleStatus
	}
	return ""
}

func checkCRLFreshness(crl *x509.RevocationList, now time.Time, configuredStatus StatusFreshnessPolicy, configuredCRL CRLFreshnessPolicy) Reason {
	status := configuredStatus.WithDefaults()
	policy := configuredCRL.WithDefaults()
	if crl.ThisUpdate.After(now.Add(status.MaxClockSkew)) {
		return ReasonFutureStatus
	}
	// MaxAge bounds the age of every CRL, including one that carries a
	// syntactically valid future NextUpdate. NextUpdate is an issuer-provided
	// validity limit, not evidence that an arbitrarily old CRL is fresh enough
	// for this experiment's signed policy.
	if now.Sub(crl.ThisUpdate) > policy.MaxAge {
		return ReasonStaleStatus
	}
	if crl.NextUpdate.IsZero() {
		if policy.RequireNextUpdate {
			return ReasonMissingFreshness
		}
		return ""
	}
	if now.After(crl.NextUpdate) {
		return ReasonStaleStatus
	}
	return ""
}

// checkRevocationTime ensures a revoked status is not asserted before the
// asserted revocation time and that it is plausible for the leaf certificate.
func checkRevocationTime(revokedAt, notBefore, now time.Time, configured StatusFreshnessPolicy) Reason {
	policy := configured.WithDefaults()
	if revokedAt.IsZero() || revokedAt.Before(notBefore.Add(-policy.MaxClockSkew)) {
		return ReasonInvalidStatus
	}
	if revokedAt.After(now.Add(policy.MaxClockSkew)) {
		return ReasonFutureStatus
	}
	return ""
}

// --- shared helpers ----------------------------------------------------------

func fetchPresentedLeaf(ctx context.Context, target Target) (*x509.Certificate, string, error) {
	addr := fmt.Sprintf("%s:%d", targetConnectHost(target), target.Port)
	// This discovery connection intentionally bypasses chain verification, but
	// the certificate identity is then bound to the exact leaf issued for this
	// cycle. Independence applies to the status-delivery path, not the subject.
	// #nosec G402 -- exact DER fingerprint binding is enforced immediately below.
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target.Host,
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("fetchPresentedLeaf: dial: %w", err)
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, "", fmt.Errorf("fetchPresentedLeaf: dial did not return a TLS connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, "", fmt.Errorf("fetchPresentedLeaf: no peer certificates")
	}
	leaf := certs[0]
	presented, err := verifyPresentedLeaf(target, leaf)
	if err != nil {
		return nil, presented, fmt.Errorf("fetchPresentedLeaf: %w", err)
	}
	return leaf, presented, nil
}

func verifyPresentedLeaf(target Target, leaf *x509.Certificate) (string, error) {
	if leaf == nil {
		return "", fmt.Errorf("peer leaf is nil")
	}
	digest := sha256.Sum256(leaf.Raw)
	presented := hex.EncodeToString(digest[:])
	if target.IssuedLeafSHA256 == "" {
		return presented, fmt.Errorf("issued leaf SHA-256 is required")
	}
	if !strings.EqualFold(presented, target.IssuedLeafSHA256) {
		return presented, fmt.Errorf("peer leaf SHA-256 %s does not match issued canary %s", presented, target.IssuedLeafSHA256)
	}
	return presented, nil
}

var statusHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := statusHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	const maxStatusBodyBytes = 4 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxStatusBodyBytes {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", url, maxStatusBodyBytes)
	}
	return body, nil
}
