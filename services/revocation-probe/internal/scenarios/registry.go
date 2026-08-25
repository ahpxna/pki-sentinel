// Package scenarios loads versioned assurance contracts independently from
// profile implementations. A manifest is strict, content-addressed input to a
// measurement cycle rather than an optional runtime hint.
package scenarios

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/profiles"
)

const Version = 1

// StaplingMode controls the canary's OCSP-staple behavior for a scenario.
// It is part of the versioned manifest so scenario execution is selected from
// declarative input instead of a runner-side scenario mapping.
type StaplingMode string

const (
	StaplingOn    StaplingMode = "on"
	StaplingOff   StaplingMode = "off"
	StaplingStale StaplingMode = "stale"
)

// EvidenceDependency names a timeline boundary that a profile needs before
// its post-revocation observation begins.
type EvidenceDependency string

const (
	EvidenceIssuerAck       EvidenceDependency = "issuer_ack"
	EvidenceOCSPPublished   EvidenceDependency = "ocsp_published"
	EvidenceCRLPublished    EvidenceDependency = "crl_published"
	EvidenceStaplePublished EvidenceDependency = "staple_published"
)

var knownEvidence = map[EvidenceDependency]struct{}{
	EvidenceIssuerAck: {}, EvidenceOCSPPublished: {}, EvidenceCRLPublished: {}, EvidenceStaplePublished: {},
}

type yamlExpectation struct {
	Decision string   `yaml:"decision" json:"decision"`
	Reasons  []string `yaml:"reasons" json:"reasons"`
}

type yamlBaseline struct {
	Before yamlExpectation `yaml:"before" json:"before"`
	After  yamlExpectation `yaml:"after" json:"after"`
}

type yamlPolicy struct {
	After yamlExpectation `yaml:"after" json:"after"`
}

type yamlProfileContract struct {
	Baseline yamlBaseline `yaml:"baseline" json:"baseline"`
	Policy   yamlPolicy   `yaml:"policy" json:"policy"`
}

type yamlExecution struct {
	Stapling StaplingMode `yaml:"stapling" json:"stapling"`
}

type yamlManifest struct {
	ID                   string                          `yaml:"id" json:"id"`
	Version              int                             `yaml:"version" json:"version"`
	EvidenceDependencies map[string][]EvidenceDependency `yaml:"evidence_dependencies" json:"evidence_dependencies"`
	Profiles             map[string]yamlProfileContract  `yaml:"profiles" json:"profiles"`
	Execution            yamlExecution                   `yaml:"execution" json:"execution"`
}

// Contract preserves the established baseline and policy contracts for one
// implementation within a scenario.
type Contract struct {
	Baseline profiles.Expectation
	Policy   profiles.Expectation
}

// Manifest is the validated, typed form of one scenario document.
type Manifest struct {
	ID                   profiles.Scenario
	Version              int
	Digest               string
	EvidenceDependencies map[string][]EvidenceDependency
	Profiles             map[string]Contract
	Stapling             StaplingMode
}

// Registry provides scenario contracts and their digests by stable ID.
type Registry struct {
	manifests map[profiles.Scenario]Manifest
}

// New constructs an in-memory registry for focused runner tests. Production
// code must use LoadDir so contracts are schema-validated and digested.
func New(manifests ...Manifest) *Registry {
	registry := &Registry{manifests: make(map[profiles.Scenario]Manifest, len(manifests))}
	for _, manifest := range manifests {
		registry.manifests[manifest.ID] = manifest
	}
	return registry
}

func validDecision(value string) (profiles.Decision, bool) {
	d := profiles.Decision(value)
	switch d {
	case profiles.DecisionAccept, profiles.DecisionReject, profiles.DecisionInconclusive, profiles.DecisionHarnessError:
		return d, true
	default:
		return "", false
	}
}

func validReason(value string) (profiles.Reason, bool) {
	r := profiles.Reason(value)
	switch r {
	case profiles.ReasonStatusGood, profiles.ReasonRevoked, profiles.ReasonExpired, profiles.ReasonMissingStatus,
		profiles.ReasonInvalidStatus, profiles.ReasonStaleStatus, profiles.ReasonFutureStatus, profiles.ReasonMissingFreshness,
		profiles.ReasonUnknownStatus, profiles.ReasonNoRevocationCheck, profiles.ReasonNetworkFailure, profiles.ReasonTLSFailure,
		profiles.ReasonClientPolicy, profiles.ReasonHarnessFailure:
		return r, true
	default:
		return "", false
	}
}

func parseExpectation(value yamlExpectation, required bool, field string) (profiles.Expectation, error) {
	if value.Decision == "" && !required {
		return profiles.Expectation{}, nil
	}
	decision, ok := validDecision(value.Decision)
	if !ok {
		return profiles.Expectation{}, fmt.Errorf("%s has unknown decision %q", field, value.Decision)
	}
	if len(value.Reasons) == 0 {
		return profiles.Expectation{}, fmt.Errorf("%s must declare at least one reason", field)
	}
	reasons := make([]profiles.Reason, 0, len(value.Reasons))
	for _, raw := range value.Reasons {
		reason, ok := validReason(raw)
		if !ok {
			return profiles.Expectation{}, fmt.Errorf("%s has unknown reason %q", field, raw)
		}
		reasons = append(reasons, reason)
	}
	return profiles.Expectation{After: decision, AfterReasons: reasons}, nil
}

func parseBaseline(value yamlBaseline, field string) (profiles.Expectation, error) {
	before, err := parseExpectation(value.Before, true, field+".before")
	if err != nil {
		return profiles.Expectation{}, err
	}
	after, err := parseExpectation(value.After, true, field+".after")
	if err != nil {
		return profiles.Expectation{}, err
	}
	return profiles.Expectation{Before: before.After, BeforeReasons: before.AfterReasons, After: after.After, AfterReasons: after.AfterReasons}, nil
}

func parsePolicy(value yamlPolicy, field string) (profiles.Expectation, error) {
	after, err := parseExpectation(value.After, true, field+".after")
	if err != nil {
		return profiles.Expectation{}, err
	}
	return profiles.Expectation{After: after.After, AfterReasons: after.AfterReasons}, nil
}

func decode(path string) (yamlManifest, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return yamlManifest{}, err
	}
	var manifest yamlManifest
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		return yamlManifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return yamlManifest{}, fmt.Errorf("multiple YAML documents are not allowed")
		}
		return yamlManifest{}, err
	}
	return manifest, nil
}

func canonicalDigest(manifest yamlManifest) (string, error) {
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("canonical JSON: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func knownProfiles(values []profiles.Profile) map[string]struct{} {
	known := make(map[string]struct{}, len(values))
	for _, profile := range values {
		known[profile.Name] = struct{}{}
	}
	return known
}

func build(raw yamlManifest, profilesByName map[string]struct{}) (Manifest, error) {
	if raw.ID == "" {
		return Manifest{}, fmt.Errorf("id is required")
	}
	if raw.Version != Version {
		return Manifest{}, fmt.Errorf("scenario %q has unsupported version %d", raw.ID, raw.Version)
	}
	if len(raw.Profiles) == 0 {
		return Manifest{}, fmt.Errorf("scenario %q has no profiles", raw.ID)
	}
	switch raw.Execution.Stapling {
	case StaplingOn, StaplingOff, StaplingStale:
	default:
		return Manifest{}, fmt.Errorf("scenario %q has invalid execution.stapling %q", raw.ID, raw.Execution.Stapling)
	}
	digest, err := canonicalDigest(raw)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{ID: profiles.Scenario(raw.ID), Version: raw.Version, Digest: digest, EvidenceDependencies: raw.EvidenceDependencies, Profiles: make(map[string]Contract, len(raw.Profiles)), Stapling: raw.Execution.Stapling}
	for name, rawContract := range raw.Profiles {
		if _, ok := profilesByName[name]; !ok {
			return Manifest{}, fmt.Errorf("scenario %q references unknown profile %q", raw.ID, name)
		}
		baseline, err := parseBaseline(rawContract.Baseline, fmt.Sprintf("scenario %q profile %q baseline", raw.ID, name))
		if err != nil {
			return Manifest{}, err
		}
		policy, err := parsePolicy(rawContract.Policy, fmt.Sprintf("scenario %q profile %q policy", raw.ID, name))
		if err != nil {
			return Manifest{}, err
		}
		manifest.Profiles[name] = Contract{Baseline: baseline, Policy: policy}
	}
	for profile := range raw.Profiles {
		if _, ok := raw.EvidenceDependencies[profile]; !ok {
			return Manifest{}, fmt.Errorf("scenario %q profile %q has no evidence dependencies", raw.ID, profile)
		}
	}
	for profile, dependencies := range raw.EvidenceDependencies {
		if _, ok := profilesByName[profile]; !ok {
			return Manifest{}, fmt.Errorf("scenario %q has evidence dependencies for unknown profile %q", raw.ID, profile)
		}
		seen := make(map[EvidenceDependency]struct{}, len(dependencies))
		if len(dependencies) == 0 {
			return Manifest{}, fmt.Errorf("scenario %q profile %q has an empty evidence dependency list", raw.ID, profile)
		}
		for _, dependency := range dependencies {
			if _, ok := knownEvidence[dependency]; !ok {
				return Manifest{}, fmt.Errorf("scenario %q profile %q has unknown evidence dependency %q", raw.ID, profile, dependency)
			}
			if _, duplicate := seen[dependency]; duplicate {
				return Manifest{}, fmt.Errorf("scenario %q profile %q repeats evidence dependency %q", raw.ID, profile, dependency)
			}
			seen[dependency] = struct{}{}
		}
		if _, requiresStaple := seen[EvidenceStaplePublished]; requiresStaple && raw.Execution.Stapling != StaplingOn {
			return Manifest{}, fmt.Errorf("scenario %q profile %q requires staple_published but execution.stapling is %q", raw.ID, profile, raw.Execution.Stapling)
		}
	}
	return manifest, nil
}

// LoadDir loads every YAML manifest in directory. File ordering cannot change
// registry semantics or individual manifest digests.
func LoadDir(directory string, implementations []profiles.Profile) (*Registry, error) {
	paths, err := filepath.Glob(filepath.Join(directory, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("scenario glob: %w", err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no scenario manifests in %s", directory)
	}
	known := knownProfiles(implementations)
	registry := &Registry{manifests: make(map[profiles.Scenario]Manifest, len(paths))}
	for _, path := range paths {
		raw, err := decode(path)
		if err != nil {
			return nil, fmt.Errorf("scenario %s: %w", path, err)
		}
		manifest, err := build(raw, known)
		if err != nil {
			return nil, fmt.Errorf("scenario %s: %w", path, err)
		}
		if _, exists := registry.manifests[manifest.ID]; exists {
			return nil, fmt.Errorf("duplicate scenario %q", manifest.ID)
		}
		registry.manifests[manifest.ID] = manifest
	}
	return registry, nil
}

func (r *Registry) Contract(scenario profiles.Scenario, profile string) (Contract, bool) {
	if r == nil {
		return Contract{}, false
	}
	manifest, ok := r.manifests[scenario]
	if !ok {
		return Contract{}, false
	}
	contract, ok := manifest.Profiles[profile]
	return contract, ok
}

func (r *Registry) Digest(scenario profiles.Scenario) (string, bool) {
	if r == nil {
		return "", false
	}
	manifest, ok := r.manifests[scenario]
	return manifest.Digest, ok
}

// Manifest returns the selected executable scenario and its validated
// execution settings. Callers must resolve it before any issuer side effect.
func (r *Registry) Manifest(scenario profiles.Scenario) (Manifest, bool) {
	if r == nil {
		return Manifest{}, false
	}
	manifest, ok := r.manifests[scenario]
	return manifest, ok
}

// Dependencies returns a copy of the evidence boundaries that gate a
// profile's post-revocation measurement.
func (r *Registry) Dependencies(scenario profiles.Scenario, profile string) ([]EvidenceDependency, bool) {
	manifest, ok := r.Manifest(scenario)
	if !ok {
		return nil, false
	}
	dependencies, ok := manifest.EvidenceDependencies[profile]
	if !ok {
		return nil, false
	}
	return append([]EvidenceDependency(nil), dependencies...), true
}

// ValidateEnabledProfiles requires the baseline and policy contract for every
// enabled implementation in every loaded scenario.
func (r *Registry) ValidateEnabledProfiles(enabled []string) error {
	for scenario, manifest := range r.manifests {
		for _, profile := range enabled {
			if _, ok := manifest.Profiles[profile]; !ok {
				return fmt.Errorf("scenario %q has no baseline contract for enabled profile %q", scenario, profile)
			}
		}
	}
	return nil
}
