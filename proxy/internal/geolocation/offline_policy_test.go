package geolocation

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
)

type rejectGeolocationTransport struct{ calls int }

func (r *rejectGeolocationTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, errors.New("unexpected geolocation HTTP request")
}

func TestGoreeCloudProxyGeolocationNeverDownloadsMissingData(t *testing.T) {
	transport := &rejectGeolocationTransport{}
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: transport}
	t.Cleanup(func() { http.DefaultClient = previous })

	missing := filepath.Join(t.TempDir(), "not-created")
	if path, err := ensureMMDB(log.New(), missing); err == nil || path != "" {
		t.Fatalf("missing local data must fail closed: path=%q err=%v", path, err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory must not be created: %v", err)
	}
	lookup, err := NewLookup(log.New(), missing)
	if err != nil || lookup != nil {
		t.Fatalf("unavailable database must disable geolocation safely: lookup=%v err=%v", lookup, err)
	}
	if transport.calls != 0 {
		t.Fatalf("unexpected outbound requests: %d", transport.calls)
	}
}

func TestGoreeCloudProxyGeolocationPreservesLocalDatabase(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "GeoLite2-City_20261024.mmdb")
	data := []byte("operator-provisioned-placeholder")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := ensureMMDB(log.New(), dir)
	if err != nil || path != file {
		t.Fatalf("expected existing file: path=%q err=%v", path, err)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != string(data) {
		t.Fatalf("existing database must not be modified: got=%q err=%v", got, err)
	}
}
