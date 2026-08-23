// Package executor exposes one profile through a small internal HTTP API.
// Compose uses one process/container per profile, which ensures that a client
// observation is not merely a second subprocess in the controller container.
package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

const maxRequestBytes = 1 << 20

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
		response, err := http.DefaultClient.Do(req)
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
		return observation, nil
	}
	return profile
}

// ApplyRemote replaces profiles named by URLs with remote executors. Entries
// use profile=url pairs; malformed or unknown profile names are rejected at
// process startup rather than silently falling back to local execution.
func ApplyRemote(registry []profiles.Profile, urls map[string]string) ([]profiles.Profile, error) {
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
		urls[name] = url
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
		defer r.Body.Close()
		var target profiles.Target
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&target); err != nil {
			http.Error(w, "invalid probe target", http.StatusBadRequest)
			return
		}
		probeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		observation, err := selected.Probe(probeCtx, target)
		if err != nil {
			observation.Decision = profiles.DecisionHarnessError
			observation.Reason = profiles.ReasonHarnessFailure
		}
		observation.Evidence.Executor = executorID
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(observation)
	})

	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
