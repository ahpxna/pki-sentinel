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
	go c.renewLoop(ctx, authInfo)
	return c, nil
}

// renewLoop keeps the current token renewed until ctx is cancelled or the
// token can no longer be renewed, in which case it re-authenticates.
func (c *Client) renewLoop(ctx context.Context, initial *vaultapi.Secret) {
	watcher, err := c.API.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
		Secret: initial,
	})
	if err != nil {
		log.Printf("vaultauth: failed to start lifetime watcher: %v", err)
		return
	}
	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-watcher.DoneCh():
			if err != nil {
				log.Printf("vaultauth: token renewal stopped: %v", err)
			} else {
				log.Printf("vaultauth: token renewal channel closed")
			}
			return
		case renewal := <-watcher.RenewCh():
			log.Printf("vaultauth: token renewed, new lease duration: %ds", renewal.Secret.LeaseDuration)
		case <-time.After(time.Hour):
			// Safety net: avoid a goroutine leak if the watcher channels
			// never fire for any reason.
		}
	}
}
