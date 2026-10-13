package metrics

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/metrics/remoteconfig"
)

const (
	// defaultPushInterval is the default interval for pushing metrics
	defaultPushInterval = 5 * time.Minute
)

// PushConfig holds configuration for metrics push
type PushConfig struct {
	// ServerAddress is the metrics server URL. If nil, uses remote config server_url.
	ServerAddress *url.URL
	// Interval is how often to push metrics. If 0, uses remote config interval or defaultPushInterval.
	Interval time.Duration
	// ForceSending skips remote configuration fetch and version checks, pushing unconditionally.
	ForceSending bool
}

// PushConfigFromEnv builds a PushConfig from environment variables.
func PushConfigFromEnv() PushConfig {
	config := PushConfig{}

	config.ForceSending = isForceSending()
	config.ServerAddress = getMetricsServerURL()
	config.Interval = getMetricsInterval()

	return config
}

// remoteConfigProvider abstracts remote push config fetching for testability
type remoteConfigProvider interface {
	RefreshIfNeeded(ctx context.Context) *remoteconfig.Config
}

// Push handles periodic pushing of metrics
type Push struct {
	metrics       metricsImplementation
	configManager remoteConfigProvider
	agentVersion  *goversion.Version

	peerID string
	peerMu sync.RWMutex

	client          *http.Client
	cfgForceSending bool
	cfgInterval     time.Duration
	cfgAddress      *url.URL
}

// validMetricsDestination allows only explicit, credential-free HTTPS URLs.
// Plain HTTP is restricted to loopback development endpoints.
func validMetricsDestination(target *url.URL) bool {
	if target == nil || (target.Scheme != "http" && target.Scheme != "https") ||
		target.Hostname() == "" || target.User != nil || target.Opaque != "" ||
		target.Fragment != "" || target.RawFragment != "" {
		return false
	}
	if target.Scheme == "https" {
		return true
	}
	if strings.EqualFold(target.Hostname(), "localhost") {
		return true
	}
	address, err := netip.ParseAddr(target.Hostname())
	return err == nil && address.Unmap().IsLoopback()
}

// NewPush creates a new Push instance with configuration resolution
func NewPush(metrics metricsImplementation, configManager remoteConfigProvider, config PushConfig, agentVersion string) (*Push, error) {
	if config.ServerAddress != nil && !validMetricsDestination(config.ServerAddress) {
		return nil, fmt.Errorf("metrics push server URL must use HTTPS, except loopback HTTP, without credentials or fragments")
	}
	var cfgInterval time.Duration
	var cfgAddress *url.URL

	if config.ForceSending {
		cfgInterval = config.Interval
		if config.Interval <= 0 {
			cfgInterval = defaultPushInterval
		}

		cfgAddress = config.ServerAddress
		if cfgAddress == nil {
			return nil, fmt.Errorf("forced metrics push requires an explicitly configured server URL")
		}
	} else {
		cfgAddress = config.ServerAddress

		if config.Interval < 0 {
			log.Warnf("negative metrics push interval %s", config.Interval)
		} else {
			cfgInterval = config.Interval
		}
	}

	parsedVersion, err := goversion.NewVersion(agentVersion)
	if err != nil {
		if !config.ForceSending {
			return nil, fmt.Errorf("parse agent version %q: %w", agentVersion, err)
		}
	}

	return &Push{
		metrics:         metrics,
		configManager:   configManager,
		agentVersion:    parsedVersion,
		cfgForceSending: config.ForceSending,
		cfgInterval:     cfgInterval,
		cfgAddress:      cfgAddress,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Never forward potentially identifying metrics to an unreviewed
			// redirect destination. A redirect is a failed delivery.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// SetPeerID updates the hashed peer ID used for the Authorization header.
func (p *Push) SetPeerID(peerID string) {
	p.peerMu.Lock()
	p.peerID = peerID
	p.peerMu.Unlock()
}

// Start starts the periodic push loop.
// The env interval override controls tick frequency but does not bypass remote config
// version gating. Use ForceSending to skip remote config entirely.
func (p *Push) Start(ctx context.Context) {
	// Log initial state
	switch {
	case p.cfgForceSending:
		log.Infof("started metrics push with forced delivery, interval %s", p.cfgInterval)
	case p.cfgAddress != nil:
		log.Info("started metrics push with explicit server URL override")
	default:
		log.Infof("started metrics push, server URL will be resolved from remote config")
	}

	timer := time.NewTimer(0) // fire immediately on first iteration
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Debug("stopping metrics push")
			return
		case <-timer.C:
		}

		pushURL, interval := p.resolve(ctx)
		if pushURL != "" {
			if err := p.push(ctx, pushURL); err != nil {
				log.Errorf("failed to push metrics: %v", err)
			}
		}

		if interval <= 0 {
			interval = defaultPushInterval
		}
		timer.Reset(interval)
	}
}

// resolve returns the push URL and interval for the next cycle.
// Returns empty pushURL to skip this cycle.
func (p *Push) resolve(ctx context.Context) (pushURL string, interval time.Duration) {
	if p.cfgForceSending {
		return p.resolveServerURL(nil), p.cfgInterval
	}

	if p.configManager == nil {
		log.Debug("metrics configuration provider unavailable; not sending")
		return "", defaultPushInterval
	}
	config := p.configManager.RefreshIfNeeded(ctx)
	if config == nil {
		log.Debug("no metrics push config available, waiting to retry")
		return "", defaultPushInterval
	}

	// prefer env variables instead of remote config
	if p.cfgInterval > 0 {
		interval = p.cfgInterval
	} else {
		interval = config.Interval
	}

	if !isVersionInRange(p.agentVersion, config.VersionSince, config.VersionUntil) {
		log.Debugf("agent version %s not in range [%s, %s), skipping metrics push",
			p.agentVersion, config.VersionSince, config.VersionUntil)
		return "", interval
	}

	pushURL = p.resolveServerURL(&config.ServerURL)
	if pushURL == "" {
		log.Warn("no metrics server URL available, skipping push")
	}
	return pushURL, interval
}

// push exports metrics and sends them to the metrics server
func (p *Push) push(ctx context.Context, pushURL string) error {
	if !safeMetricsPushURL(pushURL) {
		return fmt.Errorf("metrics push destination rejected by transport policy")
	}
	// Export metrics without clearing
	var buf bytes.Buffer
	if err := p.metrics.Export(&buf); err != nil {
		return fmt.Errorf("export metrics: %w", err)
	}

	// Don't push if there are no metrics
	if buf.Len() == 0 {
		log.Tracef("no metrics to push")
		return nil
	}

	// Gzip compress the body
	compressed, err := gzipCompress(buf.Bytes())
	if err != nil {
		return fmt.Errorf("gzip compress: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", pushURL, compressed)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Content-Encoding", "gzip")

	p.peerMu.RLock()
	peerID := p.peerID
	p.peerMu.RUnlock()
	if peerID != "" {
		req.Header.Set("X-Peer-ID", peerID)
	}

	// Send request
	resp, err := p.client.Do(req)
	if err != nil {
		// http.Client may wrap failures in url.Error, whose string contains
		// the complete configured URL (including sensitive query parameters).
		// The destination is intentionally not included in telemetry errors.
		return fmt.Errorf("metrics transport request failed (%T)", err)
	}
	defer func() {
		if resp.Body == nil {
			return
		}
		if err := resp.Body.Close(); err != nil {
			log.Warnf("failed to close response body: %v", err)
		}
	}()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("push failed with status %d", resp.StatusCode)
	}

	log.Debug("metrics push succeeded")
	p.metrics.Reset()
	return nil
}

// resolveServerURL determines the push URL.
// Precedence: envAddress (env var) > remote config server_url
func (p *Push) resolveServerURL(remoteServerURL *url.URL) string {
	var baseURL *url.URL
	if p.cfgAddress != nil {
		baseURL = p.cfgAddress
	} else {
		baseURL = remoteServerURL
	}

	if baseURL == nil {
		return ""
	}
	if !validMetricsDestination(baseURL) {
		log.Warn("metrics destination invalid; skipping telemetry")
		return ""
	}
	return baseURL.String()
}

// gzipCompress compresses data using gzip and returns the compressed buffer.
func gzipCompress(data []byte) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

// isVersionInRange checks if current falls within [since, until)
func isVersionInRange(current, since, until *goversion.Version) bool {
	return !current.LessThan(since) && current.LessThan(until)
}
