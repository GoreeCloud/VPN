package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func guardedRequest(h http.Handler, host, origin, remote, fetchSite string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://"+host+"/healthz", nil)
	r.Host = host
	r.RemoteAddr = remote
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if fetchSite != "" {
		r.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthorityBrowserOriginAndCrossSiteDenial(t *testing.T) {
	calls := 0
	handler := boundManagement(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(200)
	}), "127.0.0.1:8788", false)
	tests := []struct {
		name, host, origin, site string
		code                     int
	}{
		{"normal-laptop", "127.0.0.1:8788", "", "", 200},
		{"same-origin-browser", "127.0.0.1:8788", "http://127.0.0.1:8788", "same-origin", 200},
		{"dns-rebinding", "evil.example:8788", "", "", 421},
		{"cross-origin", "127.0.0.1:8788", "https://evil.example", "cross-site", 403},
		{"opaque-browser", "127.0.0.1:8788", "null", "", 403},
		{"cross-site-fetch", "127.0.0.1:8788", "", "cross-site", 403},
		{"wrong-port", "127.0.0.1:8789", "", "", 421},
		{"wrong-scheme", "127.0.0.1:8788", "https://127.0.0.1:8788", "", 403},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := guardedRequest(handler, tc.host, tc.origin, "127.0.0.1:53001", tc.site)
			if w.Code != tc.code {
				t.Fatalf("expected %d got %d: %s", tc.code, w.Code, w.Body.String())
			}
			if w.Code != 200 && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("denied response cached")
			}
		})
	}
	if calls != 2 {
		t.Fatalf("request reached API despite failing validation: %d", calls)
	}
}

func TestTLSOriginAndMultipleHeaders(t *testing.T) {
	api := boundManagement(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }), "[::1]:8788", true)
	r := httptest.NewRequest("GET", "https://[::1]:8788/healthz", nil)
	r.RemoteAddr = "[::1]:9001"
	r.Header.Set("Origin", "https://[::1]:8788")
	ok := httptest.NewRecorder()
	api.ServeHTTP(ok, r)
	if ok.Code != 200 {
		t.Fatalf("IPv6 HTTPS origin rejected: %d", ok.Code)
	}
	r.Header.Add("Origin", "https://[::1]:8788")
	deny := httptest.NewRecorder()
	api.ServeHTTP(deny, r)
	if deny.Code != 403 {
		t.Fatalf("duplicate Origin accepted: %d", deny.Code)
	}
}

func TestDirectPeerBudgetNoProxyTrustOrUnlimitedMap(t *testing.T) {
	clock := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	limit := newDirectLimiter()
	limit.now = func() time.Time { return clock }
	for i := 0; i < 24; i++ {
		if !limit.allow("198.18.0.15:1010") {
			t.Fatalf("request %d prematurely denied", i)
		}
	}
	if limit.allow("198.18.0.15:1010") {
		t.Fatal("rate limit failed")
	}
	if !limit.allow("198.18.0.16:1010") {
		t.Fatal("one address denied another")
	}
	if limit.allow("malformed-remote") {
		t.Fatal("malformed socket address accepted")
	}
	clock = clock.Add(time.Second)
	if !limit.allow("198.18.0.15:1010") || !limit.allow("198.18.0.15:1010") {
		t.Fatal("time refill failed")
	}
	if limit.allow("198.18.0.15:1010") {
		t.Fatal("refill exceeded 2 requests per second")
	}
}

func TestRateLimiterReturns429WithoutForwardedHeaderTrust(t *testing.T) {
	handler := boundManagement(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }), "127.0.0.1:8788", false)
	for i := 0; i < 24; i++ {
		w := guardedRequest(handler, "127.0.0.1:8788", "", "198.18.0.9:50000", "")
		if w.Code != 200 {
			t.Fatalf("unexpected limit: %d", w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:8788/healthz", nil)
	r.RemoteAddr = "198.18.0.9:50001"
	r.Header.Set("X-Forwarded-For", "203.0.113.44")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, r)
	if denied.Code != 429 || denied.Header().Get("Retry-After") != "1" {
		t.Fatalf("expected 429 got %d", denied.Code)
	}
}
