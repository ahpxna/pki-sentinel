package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ahpxna/pki-sentinel/services/revocation-probe/internal/runner"
)

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{name: "hostname", target: "https://api.internal:443", wantHost: "api.internal", wantPort: 443},
		{name: "IPv6", target: "https://[2001:db8::1]:8443/", wantHost: "2001:db8::1", wantPort: 8443},
		{name: "missing port", target: "https://api.internal", wantErr: true},
		{name: "wrong scheme", target: "http://api.internal:80", wantErr: true},
		{name: "path rejected", target: "https://api.internal:443/private", wantErr: true},
		{name: "port range", target: "https://api.internal:70000", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host, port, err := splitHostPort(test.target)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got host=%q port=%d", host, port)
				}
				return
			}
			if err != nil || host != test.wantHost || port != test.wantPort {
				t.Fatalf("got host=%q port=%d err=%v", host, port, err)
			}
		})
	}
}

func TestWriteReportJSONUsesCanonicalBytes(t *testing.T) {
	t.Parallel()
	report := &runner.CycleReport{CycleID: "cycle-1"}
	canonicalJSON, err := report.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}

	var oneShot bytes.Buffer
	if err := writeReport(&oneShot, report, "json", canonicalJSON, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oneShot.Bytes(), canonicalJSON) {
		t.Fatalf("one-shot stdout differs from canonical report: got %q want %q", oneShot.Bytes(), canonicalJSON)
	}

	var stream bytes.Buffer
	if err := writeReport(&stream, report, "json", canonicalJSON, true); err != nil {
		t.Fatal(err)
	}
	wantStream := append(append([]byte(nil), canonicalJSON...), '\n')
	if !bytes.Equal(stream.Bytes(), wantStream) {
		t.Fatalf("stream framing mismatch: got %q want %q", stream.Bytes(), wantStream)
	}
}

func TestFinalizeCycleEmitsReportWhenArchiveSinkFails(t *testing.T) {
	dir := t.TempDir()
	cycleDir := filepath.Join(dir, "cycle-archive-failure")
	if err := os.MkdirAll(cycleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cycleDir, "report.json"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &runner.CycleReport{CycleID: "cycle-archive-failure"}
	canonical, err := report.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err = finalizeCycle(report, nil, &runner.Runner{EvidenceDir: dir}, nil, "", "json", false, &stdout)
	if err == nil || !strings.Contains(err.Error(), "archive cycle report") {
		t.Fatalf("finalizeCycle error=%v, want archive failure", err)
	}
	if !bytes.Equal(stdout.Bytes(), canonical) {
		t.Fatalf("cycle disappeared from stdout after sink failure: got %q want %q", stdout.Bytes(), canonical)
	}
}
