// Package vaultauth handles AppRole login against Vault and keeps the
// resulting client token renewed for the lifetime of the process.
package vaultauth

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

// Client wraps a *vaultapi.Client that has completed AppRole login and
// keeps its token renewed via a background goroutine.
type Client struct {
	API *vaultapi.Client
}

// EnvCreds are the AppRole role_id/secret_id read from a mounted .env file
// (see .data/approle/<service>.env, written by Terraform in Step 1.8).
type EnvCreds struct {
	RoleID   string
	SecretID string
}

// LoadEnvFile parses a simple KEY=VALUE file (no shell expansion) into
// role_id / secret_id. It intentionally does not log the secret_id.
func LoadEnvFile(path string) (EnvCreds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EnvCreds{}, fmt.Errorf("reading approle env file: %w", err)
	}
	var creds EnvCreds
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "VAULT_ROLE_ID":
			creds.RoleID = parts[1]
		case "VAULT_SECRET_ID":
			creds.SecretID = parts[1]
		}
	}
	if creds.RoleID == "" || creds.SecretID == "" {
		return EnvCreds{}, fmt.Errorf("approle env file %s missing VAULT_ROLE_ID or VAULT_SECRET_ID", path)
	}
	return creds, nil
}

// Login performs AppRole login against vaultAddr and starts a renewer
// goroutine that keeps the resulting token alive for the lifetime of ctx.
func Login(ctx context.Context, vaultAddr string, creds EnvCreds) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = vaultAddr
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	secretID := &approle.SecretID{FromString: creds.SecretID}
	auth, err := approle.NewAppRoleAuth(creds.RoleID, secretID)
	if err != nil {
		return nil, fmt.Errorf("configuring approle auth: %w", err)
	}

	authInfo, err := api.Auth().Login(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("approle login: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("approle login returned no auth info")
	}

	c := &Client{API: api}
	go c.renewLoop(ctx, auth, authInfo)
	return c, nil
}

// renewLoop renews the current token and performs a fresh AppRole login when
// the token reaches token_max_ttl.
func (c *Client) renewLoop(ctx context.Context, auth vaultapi.AuthMethod, initial *vaultapi.Secret) {
	current := initial
	for {
		watcher, err := c.API.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{Secret: current})
		if err == nil {
			go watcher.Start()
			watching := true
			for watching {
				select {
				case <-ctx.Done():
					watcher.Stop()
					return
				case watchErr := <-watcher.DoneCh():
					if watchErr != nil {
						log.Printf("vaultauth: token renewal stopped: %v; re-authenticating", watchErr)
					}
					watcher.Stop()
					watching = false
				case renewal := <-watcher.RenewCh():
					if renewal != nil && renewal.Secret != nil {
						log.Printf("vaultauth: token renewed, new lease duration: %ds", renewal.Secret.LeaseDuration)
					}
				}
			}
		} else {
			log.Printf("vaultauth: failed to create lifetime watcher: %v; re-authenticating", err)
		}

		for {
			if ctx.Err() != nil {
				return
			}
			next, loginErr := c.API.Auth().Login(ctx, auth)
			if loginErr == nil && next != nil {
				current = next
				break
			}
			if loginErr == nil {
				loginErr = fmt.Errorf("login returned no auth info")
			}
			log.Printf("vaultauth: AppRole re-authentication failed: %v", loginErr)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}
}
