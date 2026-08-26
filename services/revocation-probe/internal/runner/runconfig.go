package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"sort"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

// RunConfigSnapshot is the canonical, signed description of the effective
// experiment inputs that are not already carried by the scenario manifest.
// Durations are encoded as nanoseconds to avoid text-format ambiguity.
type RunConfigSnapshot struct {
	ProfileConfigDigest string                `json:"profile_config_digest"`
	PollIntervalNS      int64                 `json:"poll_interval_ns"`
	MaxWaitNS           int64                 `json:"max_wait_ns"`
	MaxAttempts         int                   `json:"max_attempts"`
	PreflightMaxAgeNS   int64                 `json:"preflight_max_age_ns"`
	OCSPFreshness       OCSPFreshnessSnapshot `json:"ocsp_freshness"`
	Policy              PolicySnapshot        `json:"policy"`
	EnabledProfiles     []RunProfileSnapshot  `json:"enabled_profiles"`
	Build               BuildIdentity         `json:"build"`
}

type OCSPFreshnessSnapshot struct {
	MaxClockSkewNS            int64 `json:"max_clock_skew_ns"`
	RequireNextUpdate         bool  `json:"require_next_update"`
	MaxAgeWithoutNextUpdateNS int64 `json:"max_age_without_next_update_ns"`
}

type PolicySnapshot struct {
	Enforce bool `json:"enforce"`
}

type RunProfileSnapshot struct {
	Name        string               `json:"name"`
	Role        profiles.Role        `json:"role"`
	Method      profiles.CheckMethod `json:"method"`
	TimeoutNS   int64                `json:"timeout_ns"`
	ExecutorURL string               `json:"executor_url,omitempty"`
}

type BuildIdentity struct {
	GoVersion       string `json:"go_version"`
	GOOS            string `json:"goos"`
	GOARCH          string `json:"goarch"`
	BinarySHA256    string `json:"binary_sha256,omitempty"`
	OSReleaseSHA256 string `json:"os_release_sha256,omitempty"`
	VCSRevision     string `json:"vcs_revision,omitempty"`
	VCSModified     string `json:"vcs_modified,omitempty"`
	ImageDigest     string `json:"image_digest,omitempty"`
}

type profileConfigSnapshot struct {
	PollIntervalNS    int64                 `json:"poll_interval_ns"`
	MaxWaitNS         int64                 `json:"max_wait_ns"`
	MaxAttempts       int                   `json:"max_attempts"`
	PreflightMaxAgeNS int64                 `json:"preflight_max_age_ns"`
	OCSPFreshness     OCSPFreshnessSnapshot `json:"ocsp_freshness"`
	Policy            PolicySnapshot        `json:"policy"`
	EnabledProfiles   []RunProfileSnapshot  `json:"enabled_profiles"`
}

func (r *Runner) runConfigSnapshot() RunConfigSnapshot {
	profilesByName := make(map[string]profiles.Profile, len(r.Profiles))
	for _, profile := range r.Profiles {
		profilesByName[profile.Name] = profile
	}
	enabled := make([]RunProfileSnapshot, 0, len(r.Config.EnabledNames()))
	for _, name := range r.Config.EnabledNames() {
		profile, ok := profilesByName[name]
		if !ok {
			continue
		}
		enabled = append(enabled, RunProfileSnapshot{
			Name: name, Role: profile.Role, Method: profile.Method,
			TimeoutNS: int64(r.Config.TimeoutFor(name)), ExecutorURL: r.ExecutorURLs[name],
		})
	}
	sort.Slice(enabled, func(i, j int) bool { return enabled[i].Name < enabled[j].Name })
	freshness := OCSPFreshnessSnapshot{
		MaxClockSkewNS:            int64(r.Config.OCSPFreshness.MaxClockSkew),
		RequireNextUpdate:         r.Config.OCSPFreshness.RequireNextUpdate,
		MaxAgeWithoutNextUpdateNS: int64(r.Config.OCSPFreshness.MaxAgeWithoutNextUpdate),
	}
	policy := PolicySnapshot{Enforce: r.Config.Policy.Enforce}
	profileConfig := profileConfigSnapshot{
		PollIntervalNS: int64(r.Config.PollInterval), MaxWaitNS: int64(r.Config.MaxWait),
		MaxAttempts: r.Config.MaxAttempts, PreflightMaxAgeNS: int64(r.Config.PreflightMaxAge),
		OCSPFreshness: freshness, Policy: policy, EnabledProfiles: enabled,
	}
	profileConfigDigest, _ := digestJSON(profileConfig)
	return RunConfigSnapshot{
		ProfileConfigDigest: profileConfigDigest,
		PollIntervalNS:      int64(r.Config.PollInterval), MaxWaitNS: int64(r.Config.MaxWait),
		MaxAttempts: r.Config.MaxAttempts, PreflightMaxAgeNS: int64(r.Config.PreflightMaxAge),
		OCSPFreshness: freshness, Policy: policy, EnabledProfiles: enabled, Build: currentBuildIdentity(),
	}
}

func currentBuildIdentity() BuildIdentity {
	identity := BuildIdentity{
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		ImageDigest: os.Getenv("PROBE_IMAGE_DIGEST"),
	}
	if executable, err := os.Executable(); err == nil {
		identity.BinarySHA256 = fileSHA256(executable)
	}
	identity.OSReleaseSHA256 = fileSHA256("/etc/os-release")
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				identity.VCSRevision = setting.Value
			case "vcs.modified":
				identity.VCSModified = setting.Value
			}
		}
	}
	if override := os.Getenv("PROBE_BUILD_REVISION"); override != "" {
		identity.VCSRevision = override
	}
	return identity
}

func fileSHA256(path string) string {
	contents, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestRunConfig(snapshot RunConfigSnapshot) (string, error) {
	return digestJSON(snapshot)
}

func digestJSON(value any) (string, error) {
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
