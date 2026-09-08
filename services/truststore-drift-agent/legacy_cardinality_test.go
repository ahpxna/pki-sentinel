package main

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestLegacySPKIMatchCannotHideSiblingReplacement(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	original := testCertificate(t, "Shared key", now.Add(365*24*time.Hour))
	legacy := rootEntry(original)
	legacy.CertHash = ""
	replacementA, replacementB := *original, *original
	replacementA.Raw = append([]byte("replacement-a:"), original.Raw...)
	replacementB.Raw = append([]byte("replacement-b:"), original.Raw...)
	for _, tc := range []struct {
		name             string
		roots            []RootEntry
		observed         []*x509.Certificate
		changed, missing int
	}{
		{"mixed replacement", []RootEntry{legacy, rootEntry(original)}, []*x509.Certificate{&replacementA, &replacementB}, 1, 0},
		{"reversed order", []RootEntry{rootEntry(original), legacy}, []*x509.Certificate{&replacementB, &replacementA}, 1, 0},
		{"legacy and exact match", []RootEntry{legacy, rootEntry(original)}, []*x509.Certificate{&replacementA, original}, 0, 0},
		{"legacy alone", []RootEntry{legacy}, []*x509.Certificate{&replacementA}, 0, 0},
		{"extra legacy sibling", []RootEntry{legacy}, []*x509.Certificate{&replacementA, &replacementB}, 1, 0},
		{"missing legacy sibling", []RootEntry{legacy, rootEntry(original)}, []*x509.Certificate{original}, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline := Baseline{Roots: tc.roots}
			if err := validateBaseline(baseline); err != nil {
				t.Fatal(err)
			}
			result := evaluateTrustStore(baseline, tc.observed, now)
			if result.ChangedRoots != tc.changed || result.MissingRoots != tc.missing || result.UnknownRoots != 0 {
				t.Fatalf("changed=%d missing=%d unknown=%d, want changed=%d missing=%d: %+v", result.ChangedRoots, result.MissingRoots, result.UnknownRoots, tc.changed, tc.missing, result)
			}
		})
	}
}
