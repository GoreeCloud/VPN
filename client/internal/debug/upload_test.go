package debug

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/upload-server/server"
	"github.com/netbirdio/netbird/upload-server/types"
)

func TestUpload(t *testing.T) {
	if os.Getenv("DOCKER_CI") == "true" {
		t.Skip("Skipping upload test on docker ci")
	}
	testDir := t.TempDir()
	addr := reserveLoopbackPort(t)
	testURL := "http://" + addr
	t.Setenv("SERVER_URL", testURL)
	t.Setenv("SERVER_ADDRESS", addr)
	t.Setenv("STORE_DIR", testDir)
	srv := server.NewServer()
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Failed to start server: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
	})
	waitForServer(t, addr)

	file := filepath.Join(t.TempDir(), "tmpfile")
	fileContent := []byte("test file content")
	err := os.WriteFile(file, fileContent, 0640)
	require.NoError(t, err)
	key, err := UploadDebugBundle(context.Background(), testURL+types.GetURLPath, testURL, file, true)
	require.NoError(t, err)
	id := getURLHash(testURL)
	require.Contains(t, key, id+"/")
	expectedFilePath := filepath.Join(testDir, key)
	createdFileContent, err := os.ReadFile(expectedFilePath)
	require.NoError(t, err)
	require.Equal(t, fileContent, createdFileContent)
}

// reserveLoopbackPort binds an ephemeral port on loopback to learn a free
// address, then releases it so the server under test can rebind. The close/
// rebind window is racy in theory; on loopback with a kernel-assigned port
// it's essentially never contended in practice.
func reserveLoopbackPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server did not start listening on %s in time", addr)
}

func TestRequireHTTPS(t *testing.T) {
	require.NoError(t, requireHTTPS("upload URL", "https://upload.example/path"))
	require.Error(t, requireHTTPS("upload URL", "http://upload.example/path"))
	require.Error(t, requireHTTPS("upload URL", "ftp://upload.example/path"))
	require.Error(t, requireHTTPS("upload URL", "://malformed"))
	for _, raw := range []string{"https://", "https://user:pass@upload.example/", "https://upload.example/#", "https://pkgs.netbird.io/upload", "https://UPLOAD.NETBIRD.IO./upload", "https://wiretrustee.com/", "https://netbird.cloud/"} {
		require.Error(t, requireHTTPS("upload URL", raw), raw)
	}
}

func TestRejectUploadRedirect(t *testing.T) {
	require.ErrorIs(t, rejectUploadRedirect(nil, nil), http.ErrUseLastResponse)
}

// A redirect response is returned to the caller without ever contacting its
// target, even when the target uses HTTPS. This applies to both the default
// and the explicitly insecure local-development client.
func TestGoreeCloudDiagnosticClientNeverFollowsRedirects(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	client := uploadClient(false)
	client.Transport = secure.Client().Transport
	resp, err := client.Get(secure.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer insecure.Close()

	resp, err = uploadClient(true).Get(insecure.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	require.Zero(t, targetHits.Load())
}

func TestGoreeCloudDiagnosticAuthorizationNeverRedirectsOrLeaksBody(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = w.Write([]byte("private-response-body"))
	}))
	defer redirect.Close()

	_, err := getUploadURL(context.Background(), redirect.URL, "https://management.example.test", true)
	require.ErrorContains(t, err, "status 307")
	require.NotContains(t, err.Error(), "private-response-body")
	require.Zero(t, targetHits.Load())
}

func TestGoreeCloudDiagnosticPUTNeverReplaysBundle(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = w.Write([]byte("sensitive-error-detail"))
	}))
	defer redirect.Close()

	file := filepath.Join(t.TempDir(), "bundle.zip")
	require.NoError(t, os.WriteFile(file, []byte("private-bundle"), 0o600))
	err := upload(context.Background(), file, &types.GetURLResponse{URL: redirect.URL}, true)
	require.ErrorContains(t, err, "status 307")
	require.NotContains(t, err.Error(), "sensitive-error-detail")
	require.Zero(t, targetHits.Load())
}

func TestGoreeCloudDiagnosticAuthorizationResponseBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", maxUploadAuthorizationResponseSize+1)))
	}))
	defer server.Close()
	_, err := getUploadURL(context.Background(), server.URL, "https://management.example.test", true)
	require.ErrorContains(t, err, "exceeds size limit")
}

func TestGoreeCloudDiagnosticTransportErrorsDoNotEchoURLSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serviceURL := server.URL + "/private?token=very-secret-token"
	server.Close()
	_, err := getUploadURL(context.Background(), serviceURL, "https://management.example.test", true)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "very-secret-token")
	require.NotContains(t, err.Error(), "/private")
}
