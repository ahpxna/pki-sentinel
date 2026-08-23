package executor

import "testing"

func TestParseURLs(t *testing.T) {
	t.Parallel()
	urls, err := ParseURLs("curl-default=http://client-curl:8120,go-tls-default=http://client-go:8120")
	if err != nil {
		t.Fatal(err)
	}
	if urls["curl-default"] != "http://client-curl:8120" || len(urls) != 2 {
		t.Fatalf("unexpected parsed URLs: %#v", urls)
	}
	if _, err := ParseURLs("broken"); err == nil {
		t.Fatal("expected malformed entry error")
	}
}
