package remoteconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGoreeCloudInvalidConfigErrorDoesNotEchoUntrustedFieldNames(t *testing.T) {
	const marker = "credential-marker-do-not-log"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"server_url":"https://metrics.example.invalid","version-since":"1.0.0","version-until":"2.0.0","period_minutes":30,"` + marker + `":"sensitive"}`))
	}))
	defer server.Close()
	manager := NewManager(server.URL, 0)
	_, err := manager.fetch(context.Background())
	if err == nil {
		t.Fatal("unexpected config field was accepted")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("error disclosed an untrusted JSON member name")
	}
}
