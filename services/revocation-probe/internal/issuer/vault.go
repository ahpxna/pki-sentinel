// Package issuer wraps Vault's PKI secrets engine for revocation-probe:
// issuing canary certs, revoking them, and querying CRL/OCSP.
package issuer

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"golang.org/x/crypto/ocsp"
)

// CanaryCert is the material returned by IssueCanary.
type CanaryCert struct {
	CertPEM      string
	KeyPEM       string
	ChainPEM     string
	IssuerPEM    string
	SerialNumber string
	Cert         *x509.Certificate
	IssuerCert   *x509.Certificate
}

// Client wraps a logged-in Vault API client scoped to the `canary` role.
type Client struct {
	API *vaultapi.Client
}

const maxStatusResponseBytes = 4 << 20

var statusHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		// Status URLs are security-sensitive issuer endpoints. Do not silently
		// follow a redirect to a host that was never part of the experiment.
		return http.ErrUseLastResponse
	},
}

func readStatusBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, maxStatusResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxStatusResponseBytes {
		return nil, fmt.Errorf("status response exceeds %d bytes", maxStatusResponseBytes)
	}
	return data, nil
}

// Login performs AppRole login against vaultAddr using roleID/secretID.
func Login(ctx context.Context, vaultAddr, roleID, secretID string) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = vaultAddr
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("issuer: creating vault client: %w", err)
	}

	sid := &approle.SecretID{FromString: secretID}
	auth, err := approle.NewAppRoleAuth(roleID, sid)
	if err != nil {
		return nil, fmt.Errorf("issuer: configuring approle auth: %w", err)
	}
	authInfo, err := api.Auth().Login(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("issuer: approle login: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("issuer: approle login returned no auth info")
	}
	go maintainToken(ctx, api, auth, authInfo)
	return &Client{API: api}, nil
}

// maintainToken renews the current token and re-authenticates when its
// maximum TTL is reached. Without the re-login path, the long-running probe
// silently stops working after token_max_ttl (four hours in Terraform).
func maintainToken(ctx context.Context, api *vaultapi.Client, auth vaultapi.AuthMethod, secret *vaultapi.Secret) {
	current := secret
	for {
		watcher, err := api.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{Secret: current})
		if err == nil {
			go watcher.Start()
			watching := true
			for watching {
				select {
				case <-ctx.Done():
					watcher.Stop()
					return
				case renewal := <-watcher.RenewCh():
					if renewal != nil && renewal.Secret != nil {
						log.Printf("issuer: token renewed, lease duration=%ds", renewal.Secret.LeaseDuration)
					}
				case watchErr := <-watcher.DoneCh():
					if watchErr != nil {
						log.Printf("issuer: token renewal stopped: %v; re-authenticating", watchErr)
					}
					watcher.Stop()
					watching = false
				}
			}
		} else {
			log.Printf("issuer: failed to create token watcher: %v; re-authenticating", err)
		}

		for {
			if ctx.Err() != nil {
				return
			}
			next, loginErr := api.Auth().Login(ctx, auth)
			if loginErr == nil && next != nil {
				current = next
				break
			}
			if loginErr == nil {
				loginErr = fmt.Errorf("login returned no auth info")
			}
			log.Printf("issuer: AppRole re-authentication failed: %v", loginErr)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}
}

// IssueCanary requests a short-lived canary certificate for cn from the
// `canary` PKI role.
func (c *Client) IssueCanary(ctx context.Context, cn string) (*CanaryCert, error) {
	secret, err := c.API.Logical().WriteWithContext(ctx, "pki_int/issue/canary", map[string]interface{}{
		"common_name": cn,
	})
	if err != nil {
		return nil, fmt.Errorf("issuer: issue canary: %w", err)
	}

	certPEM, _ := secret.Data["certificate"].(string)
	keyPEM, _ := secret.Data["private_key"].(string)
	serial, _ := secret.Data["serial_number"].(string)
	issuerPEM, _ := secret.Data["issuing_ca"].(string)

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("issuer: could not decode canary certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuer: parsing canary certificate: %w", err)
	}
	issuerBlock, _ := pem.Decode([]byte(issuerPEM))
	if issuerBlock == nil {
		return nil, fmt.Errorf("issuer: could not decode issuing CA certificate PEM")
	}
	issuerCert, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuer: parsing issuing CA certificate: %w", err)
	}

	chain := pemStrings(secret.Data["ca_chain"])
	if len(chain) == 0 {
		chain = []string{issuerPEM}
	}

	return &CanaryCert{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		ChainPEM:     strings.Join(chain, "\n"),
		IssuerPEM:    issuerPEM,
		SerialNumber: serial,
		Cert:         cert,
		IssuerCert:   issuerCert,
	}, nil
}

func pemStrings(value interface{}) []string {
	var result []string
	switch values := value.(type) {
	case []interface{}:
		for _, value := range values {
			if pemValue, ok := value.(string); ok && pemValue != "" {
				result = append(result, pemValue)
			}
		}
	case []string:
		for _, pemValue := range values {
			if pemValue != "" {
				result = append(result, pemValue)
			}
		}
	}
	return result
}

// Revoke revokes the certificate identified by serial.
//
// RevokedAt is captured from the client side immediately AFTER the revoke
// API call returns (t_response), not before it (t_request). t_response is
// the earliest instant the revocation is guaranteed durable in Vault's
// storage — the same measurement discipline used in the original CYB 260
// methodology, where detection time was defined relative to the CA-side
// revocation timestamp rather than the moment the client issued the
// request.
func (c *Client) Revoke(ctx context.Context, serial string) (tRequest, tResponse time.Time, err error) {
	tRequest = time.Now()
	_, err = c.API.Logical().WriteWithContext(ctx, "pki_int/revoke", map[string]interface{}{
		"serial_number": serial,
	})
	tResponse = time.Now()
	if err != nil {
		return tRequest, tResponse, fmt.Errorf("issuer: revoke %s: %w", serial, err)
	}
	return tRequest, tResponse, nil
}

// FetchCRL downloads and parses the current CRL from pki_int.
func (c *Client) FetchCRL(ctx context.Context, crlURL string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := statusHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issuer: fetching CRL: %w", err)
	}
	defer resp.Body.Close()
	body, err := readStatusBody(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("issuer: CRL endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("issuer: parsing CRL: %w", err)
	}
	return crl, nil
}

// FetchOCSPResponse builds and sends a raw OCSP request and returns both the
// DER response (suitable for TLS stapling) and its certificate status.
func (c *Client) FetchOCSPResponse(ctx context.Context, ocspURL string, cert, issuerCert *x509.Certificate) ([]byte, int, error) {
	reqBytes, err := ocsp.CreateRequest(cert, issuerCert, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("issuer: creating OCSP request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	resp, err := statusHTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("issuer: OCSP request: %w", err)
	}
	defer resp.Body.Close()
	body, err := readStatusBody(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, 0, fmt.Errorf("issuer: OCSP responder returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	parsed, err := ocsp.ParseResponseForCert(body, cert, issuerCert)
	if err != nil {
		// A "revoked" OCSP response still parses; ocsp.ParseResponseForCert
		// returns an error only for malformed responses, not for the
		// revoked status itself (that's parsed.Status == ocsp.Revoked).
		return nil, 0, fmt.Errorf("issuer: parsing OCSP response: %w", err)
	}
	return body, parsed.Status, nil
}
