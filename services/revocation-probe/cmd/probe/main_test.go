package main

import "testing"

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
