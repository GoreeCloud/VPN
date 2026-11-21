package api

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoreeCloud/VPN/internal/control"
)

const testToken = "unused-test-only-administrator-token-0123456789abcdef"

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	s, err := control.Open(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(s, testToken, "")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func req(t *testing.T, h http.Handler, method, path, token, payload string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(payload))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if payload != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func testPublicKey(t *testing.T) string {
	t.Helper()
	p, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(p.PublicKey().Bytes())
}

func TestAuthAndHealth(t *testing.T) {
	h := newHandler(t)
	if c := req(t, h, "GET", "/healthz", "", "").Code; c != 200 {
		t.Fatal(c)
	}
	for _, tok := range []string{"", "bad", strings.Repeat("x", 48)} {
		w := req(t, h, "GET", "/v1/peers", tok, "")
		if w.Code != 401 {
			t.Fatalf("unauthorized access: %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "authentication required") {
			t.Fatal("error contract")
		}
	}
	if c := req(t, h, "GET", "/v1/peers", testToken, "").Code; c != 200 {
		t.Fatal(c)
	}
	if c := req(t, h, "GET", "/v1/info", testToken, "").Code; c != 200 {
		t.Fatal(c)
	}
	if c := req(t, h, "GET", "/v1/info", "", "").Code; c != 401 {
		t.Fatal(c)
	}
	if c := req(t, h, "PATCH", "/v1/peers", testToken, "").Code; c != 405 {
		t.Fatal(c)
	}
	if c := req(t, h, "GET", "/private/credentials", testToken, "").Code; c != 404 {
		t.Fatal(c)
	}
}

func TestCreateAndRevokePeer(t *testing.T) {
	h := newHandler(t)
	key := testPublicKey(t)
	payload := fmt.Sprintf(`{"name":"laptop","public_key":%q}`, key)
	if c := req(t, h, "POST", "/v1/peers", testToken, payload).Code; c != 201 {
		t.Fatal(c)
	}
	if c := req(t, h, "POST", "/v1/peers", testToken, payload).Code; c != 409 {
		t.Fatal(c)
	}
	w := req(t, h, "GET", "/v1/peers", testToken, "")
	var got struct {
		Peers []control.Peer `json:"peers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 1 || got.Peers[0].Address != "10.77.0.2/32" {
		t.Fatalf("bad peer %+v", got.Peers)
	}
	if got.Peers[0].ApprovedAt != nil {
		t.Fatal("peer must not be automatically approved")
	}
	approval := "/v1/peers/" + got.Peers[0].ID + "/approve"
	if c := req(t, h, "POST", approval, "", "").Code; c != 401 {
		t.Fatalf("unauthorized approval: %d", c)
	}
	if c := req(t, h, "GET", approval, testToken, "").Code; c != 405 {
		t.Fatalf("wrong approval method: %d", c)
	}
	if c := req(t, h, "POST", approval, testToken, "").Code; c != 200 {
		t.Fatalf("approval failed: %d", c)
	}
	if c := req(t, h, "POST", approval, testToken, "").Code; c != 409 {
		t.Fatalf("repeated approval accepted: %d", c)
	}
	list := req(t, h, "GET", "/v1/peers", testToken, "")
	if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil || got.Peers[0].ApprovedAt == nil {
		t.Fatal("approved peer did not persist")
	}
	url := "/v1/peers/" + got.Peers[0].ID + "/revoke"
	if c := req(t, h, "POST", url, testToken, "").Code; c != 200 {
		t.Fatal(c)
	}
	if c := req(t, h, "POST", url, testToken, "").Code; c != 409 {
		t.Fatal(c)
	}
	if c := req(t, h, "POST", approval, testToken, "").Code; c != 409 {
		t.Fatalf("revoked approval allowed: %d", c)
	}

	if c := req(t, h, "GET", url, testToken, "").Code; c != 405 {
		t.Fatal(c)
	}
}

func TestStrictJSONValidation(t *testing.T) {
	h := newHandler(t)
	key := testPublicKey(t)
	tests := []struct {
		body   string
		status int
	}{
		{`{"name":"invalid/path","public_key":"x"}`, 422},
		{fmt.Sprintf(`{"name":"ok","public_key":%q,"extra":1}`, key), 400},
		{fmt.Sprintf(`{"name":"ok","public_key":%q} {"bad":1}`, key), 400},
		{strings.Repeat("A", 9000), 400},
		{`not-json`, 400},
	}
	for i, c := range tests {
		w := req(t, h, "POST", "/v1/peers", testToken, c.body)
		if w.Code != c.status {
			t.Fatalf("case %d expected %d, got %d (%s)", i, c.status, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("POST", "/v1/peers", bytes.NewReader([]byte("{}")))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatalf("unsupported content type: %d", w.Code)
	}
}

func TestTokenSafety(t *testing.T) {
	s, err := control.Open(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"short", " " + testToken, "x\n" + testToken} {
		if _, err := NewHandler(s, tok, ""); err == nil {
			t.Fatalf("accepted weak token")
		}
	}
	h, _ := NewHandler(s, testToken, "")
	r := httptest.NewRequest("GET", "/v1/peers", nil)
	r.Header.Add("Authorization", "Bearer "+testToken)
	r.Header.Add("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("duplicated auth accepted: %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive response cacheable")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal("missing CSP protection")
	}
}

func TestPeerApprovalRequiresAdminAndCannotUndoRevocation(t *testing.T) {
	h := newHandler(t)
	body := fmt.Sprintf("{\"name\":\"review-device\",\"public_key\":%q}", testPublicKey(t))
	created := req(t, h, "POST", "/v1/peers", testToken, body)
	if created.Code != 201 {
		t.Fatalf("register: %s", created.Body.String())
	}
	var pending control.Peer
	if err := json.Unmarshal(created.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if pending.ApprovedAt != nil {
		t.Fatal("registration must not authorize gateway access")
	}
	approval := "/v1/peers/" + pending.ID + "/approve"
	if got := req(t, h, "POST", approval, "", "").Code; got != 401 {
		t.Fatalf("unauthenticated approval: %d", got)
	}
	if got := req(t, h, "GET", approval, testToken, "").Code; got != 405 {
		t.Fatalf("GET approval: %d", got)
	}
	ok := req(t, h, "POST", approval, testToken, "")
	if ok.Code != 200 {
		t.Fatalf("approval: %d %s", ok.Code, ok.Body.String())
	}
	var approved control.Peer
	if err := json.Unmarshal(ok.Body.Bytes(), &approved); err != nil || approved.ApprovedAt == nil {
		t.Fatal("missing persisted approval")
	}
	if got := req(t, h, "POST", approval, testToken, "").Code; got != 409 {
		t.Fatalf("duplicate approval accepted: %d", got)
	}
	revoke := "/v1/peers/" + pending.ID + "/revoke"
	if got := req(t, h, "POST", revoke, testToken, "").Code; got != 200 {
		t.Fatalf("revocation: %d", got)
	}
	if got := req(t, h, "POST", approval, testToken, "").Code; got != 409 {
		t.Fatalf("revoked device reapproved: %d", got)
	}
	if got := req(t, h, "POST", "/v1/peers/not-a-peer/approve", testToken, "").Code; got != 404 {
		t.Fatalf("invalid ID accepted: %d", got)
	}
}
