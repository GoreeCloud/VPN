package debug

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"

	"github.com/netbirdio/netbird/upload-server/types"
)

const (
	maxBundleUploadSize = 50 * 1024 * 1024
	maxUploadAuthorizationResponseSize = 16 * 1024
)

// requireHTTPS refuses any URL the daemon would fetch or upload to that is not
// https. The daemon runs as root and the bundle carries its logs and state, so a
// plaintext hop is a place to intercept the bundle or the presigned redirect.
// The server-side gate already enforces this for the desktop path; this also
// covers the mobile and job-runner callers that reach this package directly.
// Skipped when the caller opted into an insecure upload (self-hosted server).
func requireHTTPS(what, rawURL string) error {
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid %s", what)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use https", what)
	}
	if parsed.Hostname() == "" || parsed.User != nil || strings.Contains(rawURL, "#") {
		return fmt.Errorf("%s requires a host without credentials or fragments", what)
	}
	host := strings.TrimRight(strings.ToLower(parsed.Hostname()), ".")
	for _, inherited := range []string{"netbird.io", "wiretrustee.com", "netbird.cloud"} {
		if host == inherited || strings.HasSuffix(host, "."+inherited) {
			return fmt.Errorf("%s cannot use an inherited hosted diagnostic endpoint", what)
		}
	}
	return nil
}

// uploadClient never follows redirects. A presigned upload destination is an
// explicit authorization for one URL, not permission to replay a diagnostic
// bundle or its management identifier to a redirect target.
func uploadClient(insecure bool) *http.Client {
	if !insecure {
		return &http.Client{CheckRedirect: rejectUploadRedirect}
	}
	return &http.Client{
		CheckRedirect: rejectUploadRedirect,
		Transport: &http.Transport{
			//nolint:gosec // opt-in, privileged, self-hosted upload servers
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
}

func rejectUploadRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func UploadDebugBundle(ctx context.Context, url, managementURL, filePath string, insecure bool) (key string, err error) {
	if !insecure {
		if err := requireHTTPS("upload service URL", url); err != nil {
			return "", err
		}
	}

	response, err := getUploadURL(ctx, url, managementURL, insecure)
	if err != nil {
		return "", err
	}

	if !insecure {
		if err := requireHTTPS("upload URL from service", response.URL); err != nil {
			return "", err
		}
	}

	err = upload(ctx, filePath, response, insecure)
	if err != nil {
		return "", err
	}
	return response.Key, nil
}

func upload(ctx context.Context, filePath string, response *types.GetURLResponse, insecure bool) error {
	fileData, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}

	defer fileData.Close()

	stat, err := fileData.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}

	if stat.Size() > maxBundleUploadSize {
		return fmt.Errorf("file size exceeds maximum limit of %d bytes", maxBundleUploadSize)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", response.URL, fileData)
	if err != nil {
		return fmt.Errorf("create diagnostic upload request: invalid destination")
	}

	req.ContentLength = stat.Size()
	req.Header.Set("Content-Type", "application/octet-stream")

	putResp, err := uploadClient(insecure).Do(req)
	if err != nil {
		return fmt.Errorf("diagnostic upload transport failed")
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		return fmt.Errorf("diagnostic upload status %d", putResp.StatusCode)
	}
	return nil
}

func getUploadURL(ctx context.Context, serviceURL string, managementURL string, insecure bool) (*types.GetURLResponse, error) {
	parsed, err := neturl.Parse(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("invalid diagnostic upload service URL")
	}
	q := parsed.Query()
	q.Set("id", getURLHash(managementURL))
	parsed.RawQuery = q.Encode()

	getReq, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create diagnostic authorization request: invalid destination")
	}

	getReq.Header.Set(types.ClientHeader, types.ClientHeaderValue)

	resp, err := uploadClient(insecure).Do(getReq)
	if err != nil {
		return nil, fmt.Errorf("diagnostic authorization transport failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("diagnostic authorization status %d", resp.StatusCode)
	}

	urlBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxUploadAuthorizationResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read diagnostic authorization response failed")
	}
	if len(urlBytes) > maxUploadAuthorizationResponseSize {
		return nil, fmt.Errorf("diagnostic authorization response exceeds size limit")
	}
	var response types.GetURLResponse
	if err := json.Unmarshal(urlBytes, &response); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &response, nil
}

func getURLHash(url string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(url)))
}
