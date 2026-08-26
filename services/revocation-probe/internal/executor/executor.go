// Package executor exposes one profile through a small internal HTTP API.
// Compose uses one process/container per profile, which ensures that a client
// observation is not merely a second subprocess in the controller container.
package executor

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

const maxRequestBytes = 1 << 20

var executorHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func requiredExecutorToken() (string, error) {
	token := strings.TrimSpace(os.Getenv("PROBE_EXECUTOR_TOKEN"))
	if token != "" {
		return token, nil
	}
	if os.Getenv("ALLOW_UNAUTHENTICATED_EXECUTOR") == "1" {
		return "", nil
	}
	return "", fmt.Errorf("PROBE_EXECUTOR_TOKEN is required; set ALLOW_UNAUTHENTICATED_EXECUTOR=1 only for an isolated local test")
}

// Remote returns a profile whose execution occurs at baseURL. The original
// contract remains local so the runner evaluates identical expectations for
// local and containerized execution.
func Remote(profile profiles.Profile, baseURL string) profiles.Profile {
	profile.Probe = func(ctx context.Context, target profiles.Target) (profiles.Observation, error) {
		payload, err := json.Marshal(target)
		if err != nil {
			return profiles.Observation{}, fmt.Errorf("encode executor target: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/probe", bytes.NewReader(payload))
		if err != nil {
			return profiles.Observation{}, fmt.Errorf("create executor request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		token, err := requiredExecutorToken()
		if err != nil {
			return profiles.Observation{}, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := executorHTTPClient.Do(req)
		if err != nil {
			// An executor API is harness infrastructure. Its failure must not be
			// recorded as a relying-party network result.
			return profiles.Observation{}, fmt.Errorf("call executor %s: %w", profile.Name, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return profiles.Observation{}, fmt.Errorf("executor %s returned HTTP %d", profile.Name, response.StatusCode)
		}
		var observation profiles.Observation
		if err := json.NewDecoder(io.LimitReader(response.Body, maxRequestBytes)).Decode(&observation); err != nil {
			return profiles.Observation{}, fmt.Errorf("decode executor response: %w", err)
		}
		if observation.HarnessError != "" {
			return observation, fmt.Errorf("executor %s: %s", profile.Name, observation.HarnessError)
		}
		return observation, nil
	}
	return profile
}

// ApplyRemote replaces profiles named by URLs with remote executors. Entries
// use profile=url pairs; malformed or unknown profile names are rejected at
// process startup rather than silently falling back to local execution.
func ApplyRemote(registry []profiles.Profile, urls map[string]string) ([]profiles.Profile, error) {
	if len(urls) > 0 {
		if _, err := requiredExecutorToken(); err != nil {
			return nil, fmt.Errorf("remote executors: %w", err)
		}
	}
	known := make(map[string]bool, len(registry))
	result := make([]profiles.Profile, 0, len(registry))
	for _, profile := range registry {
		known[profile.Name] = true
		if url, ok := urls[profile.Name]; ok {
			if url == "" {
				return nil, fmt.Errorf("executor URL for %s is empty", profile.Name)
			}
			profile = Remote(profile, url)
		}
		result = append(result, profile)
	}
	for name := range urls {
		if !known[name] {
			return nil, fmt.Errorf("executor configured for unknown profile %q", name)
		}
	}
	return result, nil
}

// ParseURLs parses a comma-separated profile=http://executor:port list.
func ParseURLs(value string) (map[string]string, error) {
	urls := map[string]string{}
	if strings.TrimSpace(value) == "" {
		return urls, nil
	}
	for _, item := range strings.Split(value, ",") {
		name, url, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(url) == "" {
			return nil, fmt.Errorf("invalid executor entry %q; expected profile=http://host:port", item)
		}
		if _, exists := urls[name]; exists {
			return nil, fmt.Errorf("duplicate executor profile %q", name)
		}
		parsed, err := neturl.Parse(url)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return nil, fmt.Errorf("invalid executor URL for %q", name)
		}
		urls[name] = strings.TrimRight(url, "/")
	}
	return urls, nil
}

// Serve starts a health-checked executor restricted to a single profile.
func Serve(ctx context.Context, address, profileName string) error {
	var selected *profiles.Profile
	for _, profile := range profiles.Registry() {
		if profile.Name == profileName {
			copy := profile
			selected = &copy
			break
		}
	}
	if selected == nil {
		return fmt.Errorf("unknown executor profile %q", profileName)
	}
	token, err := requiredExecutorToken()
	if err != nil {
		return fmt.Errorf("executor %s: %w", profileName, err)
	}
	executorID := os.Getenv("EXECUTOR_ID")
	if executorID == "" {
		executorID = profileName
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if token != "" {
			want := []byte("Bearer " + token)
			got := []byte(r.Header.Get("Authorization"))
			if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
				http.Error(w, "unauthorized executor request", http.StatusUnauthorized)
				return
			}
		}
		defer r.Body.Close()
		var target profiles.Target
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&target); err != nil {
			http.Error(w, "invalid probe target", http.StatusBadRequest)
			return
		}
		if err := validateTarget(target); err != nil {
			http.Error(w, "disallowed probe target", http.StatusForbidden)
			return
		}
		probeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		observation, err := selected.Probe(probeCtx, target)
		if err != nil {
			observation.Decision = profiles.DecisionHarnessError
			observation.Reason = profiles.ReasonHarnessFailure
			observation.HarnessError = err.Error()
		}
		observation.Evidence.Executor = executorID
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(observation)
	})

	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func validateTarget(target profiles.Target) error {
	if allowed := os.Getenv("EXECUTOR_ALLOWED_CONNECT_HOST"); allowed != "" && target.ConnectHost != allowed {
		return fmt.Errorf("connect host %q is not allowed", target.ConnectHost)
	}
	for _, rawURL := range []string{target.OCSPURL, target.CRLURL} {
		parsed, err := neturl.Parse(rawURL)
		if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
			return fmt.Errorf("invalid status URL")
		}
		if allowed := os.Getenv("EXECUTOR_ALLOWED_STATUS_HOST"); allowed != "" && parsed.Hostname() != allowed {
			return fmt.Errorf("status host %q is not allowed", parsed.Hostname())
		}
	}
	return nil
}
