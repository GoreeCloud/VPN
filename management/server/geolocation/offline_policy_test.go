package geolocation

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type rejectManagementGeoTransport struct{ calls int }

func (r *rejectManagementGeoTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, errors.New("unexpected management geolocation HTTP request")
}

func TestGoreeCloudManagementGeolocationMissingFilesNoEgress(t *testing.T) {
	transport := &rejectManagementGeoTransport{}
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: transport}
	t.Cleanup(func() { http.DefaultClient = previous })

	dir := t.TempDir()
	for _, autoUpdate := range []bool{false, true} {
		geo, err := NewGeolocation(context.Background(), dir, autoUpdate)
		if err == nil || geo != nil {
			t.Fatalf("missing data must fail closed (autoUpdate=%v): geo=%v err=%v", autoUpdate, geo, err)
		}
	}
	if transport.calls != 0 {
		t.Fatalf("unexpected outbound requests: %d", transport.calls)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("missing database must not create files: entries=%v err=%v", entries, err)
	}
}

func TestGoreeCloudManagementGeolocationKeepsLocalVersions(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		"GeoLite2-City_20260101.mmdb", "GeoLite2-City_20261024.mmdb",
		"geonames_20260101.db", "geonames_20261024.db",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	mmdb, err := getDatabaseFilename(ctx, filepath.Join(dir, mmdbPattern))
	if err != nil || mmdb != files[1] {
		t.Fatalf("local mmdb selection: %q, %v", mmdb, err)
	}
	geonames, err := getDatabaseFilename(ctx, filepath.Join(dir, geonamesdbPattern))
	if err != nil || geonames != files[3] {
		t.Fatalf("local geonames selection: %q, %v", geonames, err)
	}
	if err := loadGeolocationDatabases(ctx, dir, mmdb, geonames); err != nil {
		t.Fatalf("existing local databases must be accepted: %v", err)
	}
	for _, name := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != "unchanged" {
			t.Fatalf("local database %s must be preserved: %q %v", name, got, err)
		}
	}
}
