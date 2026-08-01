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
	"net/http"
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
	SerialNumber string
	Cert         *x509.Certificate
}

// Client wraps a logged-in Vault API client scoped to the `canary` role.
type Client struct {
	API *vaultapi.Client
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
	if _, err := api.Auth().Login(ctx, auth); err != nil {
		return nil, fmt.Errorf("issuer: approle login: %w", err)
	}
	return &Client{API: api}, nil
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
	caChain, _ := secret.Data["issuing_ca"].(string)

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("issuer: could not decode canary certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuer: parsing canary certificate: %w", err)
	}

	return &CanaryCert{
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		ChainPEM:     certPEM + "\n" + caChain,
		SerialNumber: serial,
		Cert:         cert,
	}, nil
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issuer: fetching CRL: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("issuer: parsing CRL: %w", err)
	}
	return crl, nil
}

// QueryOCSP builds and sends a raw OCSP request for cert, signed by issuer,
// against ocspURL, and returns the parsed OCSP response status.
func (c *Client) QueryOCSP(ctx context.Context, ocspURL string, cert, issuerCert *x509.Certificate) (ocsp.ResponseStatus, error) {
	reqBytes, err := ocsp.CreateRequest(cert, issuerCert, nil)
	if err != nil {
		return 0, fmt.Errorf("issuer: creating OCSP request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(reqBytes))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("issuer: OCSP request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	parsed, err := ocsp.ParseResponseForCert(body, cert, issuerCert)
	if err != nil {
		// A "revoked" OCSP response still parses; ocsp.ParseResponseForCert
		// returns an error only for malformed responses, not for the
		// revoked status itself (that's parsed.Status == ocsp.Revoked).
		return 0, fmt.Errorf("issuer: parsing OCSP response: %w", err)
	}
	return ocsp.ResponseStatus(parsed.Status), nil
}
