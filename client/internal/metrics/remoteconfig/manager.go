package remoteconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultMinRefreshInterval = 30 * time.Minute
	maxCachedConfigAge        = 2 * time.Hour
)

// Sentinel for terminal server responses that explicitly withdraw a remote
// telemetry destination. Never include endpoint URLs or credentials.
var errConfigRevoked = errors.New("remote metrics configuration revoked")

var errConfigInvalid = errors.New("remote metrics configuration invalid")

// Config holds the parsed remote push configuration
type Config struct {
	ServerURL    url.URL
	VersionSince *goversion.Version
	VersionUntil *goversion.Version
	Interval     time.Duration
}

// rawConfig is the JSON wire format fetched from the remote server
type rawConfig struct {
	ServerURL     string `json:"server_url"`
	VersionSince  string `json:"version-since"`
	VersionUntil  string `json:"version-until"`
	PeriodMinutes int    `json:"period_minutes"`
}

// Manager handles fetching and caching remote push configuration
type Manager struct {
	configURL          string
	minRefreshInterval time.Duration
	client             *http.Client
	now                func() time.Time

	mu            sync.Mutex
	lastConfig    *Config
	lastFetched   time.Time
	lastSucceeded time.Time
}

func NewManager(configURL string, minRefreshInterval time.Duration) *Manager {
	return &Manager{
		configURL:          configURL,
		minRefreshInterval: minRefreshInterval,
		now:                time.Now,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// RefreshIfNeeded fetches new config if the cached one is stale.
// Returns the current config (possibly just fetched) or nil if unavailable.
func (m *Manager) RefreshIfNeeded(ctx context.Context) *Config {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.configURL == "" {
		m.lastConfig = nil
		m.lastSucceeded = time.Time{}
		m.lastFetched = time.Time{}
		return nil // No implicit telemetry endpoint or cached authorization.
	}
	now := m.now()
	if m.isConfigFresh(now) {
		return m.lastConfig
	}

	fetchedConfig, err := m.fetch(ctx)
	now = m.now()
	m.lastFetched = now
	if err != nil {
		if errors.Is(err, errConfigRevoked) || errors.Is(err, errConfigInvalid) {
			m.lastConfig = nil
			m.lastSucceeded = time.Time{}
			log.Warn("metrics remote configuration revoked or invalid; discarding cached destination")
			return nil
		}
		if m.cacheLeaseValid(now) {
			log.Warn("metrics remote config unavailable; retaining time-bounded cached configuration")
			return m.lastConfig
		}
		m.lastConfig = nil
		log.Warn("metrics configuration expired; stopping optional telemetry")
		return nil
	}

	m.lastConfig = fetchedConfig
	m.lastSucceeded = now

	log.Tracef("fetched metrics remote config: version-since=%s version-until=%s period=%s",
		fetchedConfig.VersionSince, fetchedConfig.VersionUntil, fetchedConfig.Interval)

	return fetchedConfig
}

func (m *Manager) isConfigFresh(now time.Time) bool {
	return m.cacheLeaseValid(now) && !m.lastFetched.After(now) && now.Sub(m.lastFetched) < m.minRefreshInterval
}

// Cached telemetry destinations expire relative to the most recent success,
// even if failures keep occurring and retries are spaced far apart.
func (m *Manager) cacheLeaseValid(now time.Time) bool {
	return m.lastConfig != nil && !m.lastSucceeded.IsZero() &&
		!m.lastSucceeded.After(now) && now.Sub(m.lastSucceeded) < maxCachedConfigAge
}

func (m *Manager) fetch(ctx context.Context) (*Config, error) {
	if !validConfigEndpoint(m.configURL) {
		return nil, fmt.Errorf("%w: metrics configuration URL rejected by transport policy", errConfigInvalid)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot construct metrics config request")
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metrics config transport request failed")
	}
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return nil, errConfigRevoked
	}
	if resp.StatusCode != http.StatusOK {
		// Only temporary overload, timeout and server failures can use the
		// remaining lease. Any other response withdraws authorization.
		if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode >= 500 && resp.StatusCode <= 599) {
			return nil, fmt.Errorf("temporary metrics config status: %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("%w: unexpected config status %d", errConfigInvalid, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil {
		// A successful response with an unreadable body cannot renew or
		// preserve the previous telemetry authorization.
		return nil, fmt.Errorf("%w: failed to read config body", errConfigInvalid)
	}

	if len(body) > 4096 {
		return nil, fmt.Errorf("%w: response exceeds 4096 bytes", errConfigInvalid)
	}

	if !uniqueConfigFields(body) {
		return nil, fmt.Errorf("%w: ambiguous or invalid config object", errConfigInvalid)
	}
	var raw rawConfig
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: malformed config object", errConfigInvalid)
	}

	if raw.PeriodMinutes <= 0 || int64(raw.PeriodMinutes) > math.MaxInt64/int64(time.Minute) {
		return nil, fmt.Errorf("%w: invalid period_minutes", errConfigInvalid)
	}

	if raw.ServerURL == "" {
		return nil, fmt.Errorf("%w: server_url is required", errConfigInvalid)
	}

	if !validConfigEndpoint(raw.ServerURL) {
		return nil, fmt.Errorf("%w: invalid metrics server destination", errConfigInvalid)
	}
	serverURL, err := url.Parse(raw.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid metrics server destination", errConfigInvalid)
	}

	since, err := goversion.NewVersion(raw.VersionSince)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid version-since", errConfigInvalid)
	}

	until, err := goversion.NewVersion(raw.VersionUntil)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid version-until", errConfigInvalid)
	}

	if !since.LessThan(until) {
		return nil, fmt.Errorf("%w: empty or inverted version range", errConfigInvalid)
	}

	return &Config{
		ServerURL:    *serverURL,
		VersionSince: since,
		VersionUntil: until,
		Interval:     time.Duration(raw.PeriodMinutes) * time.Minute,
	}, nil
}

// validConfigEndpoint permits explicit credential-free HTTPS endpoints, plus
// loopback HTTP for development; reject query parameters, fragments and URL userinfo.
func validConfigEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		strings.Contains(raw, "#") || u.Fragment != "" || u.RawFragment != "" ||
		u.RawQuery != "" || u.ForceQuery {
		return false
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if portText := u.Port(); portText != "" {
		port, portErr := strconv.Atoi(portText)
		if portErr != nil || port < 1 || port > 65535 {
			return false
		}
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(u.Hostname())
	return err == nil && addr.Unmap().IsLoopback()
}
