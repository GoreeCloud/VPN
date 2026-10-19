package jobexec

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/debug"
)

const (
	MaxBundleWaitTime = 60 * time.Minute // maximum wait time for bundle generation (1 hour)
)

var (
	ErrJobNotImplemented = errors.New("job not implemented")
)

type Executor struct {
}

func NewExecutor() *Executor {
	return &Executor{}
}

func (e *Executor) BundleJob(ctx context.Context, debugBundleDependencies debug.GeneratorDependencies, params debug.BundleConfig, waitForDuration time.Duration, mgmURL, uploadURL string) (string, error) {
	if err := requireExplicitDebugUploadURL(uploadURL); err != nil {
		return "", err
	}

	if waitForDuration > MaxBundleWaitTime {
		log.Warnf("bundle wait time %v exceeds maximum %v, capping to maximum", waitForDuration, MaxBundleWaitTime)
		waitForDuration = MaxBundleWaitTime
	}

	if waitForDuration > 0 {
		if err := waitFor(ctx, waitForDuration); err != nil {
			return "", err
		}
	}

	log.Infof("execute debug bundle generation")

	bundleGenerator := debug.NewBundleGenerator(debugBundleDependencies, params)

	path, err := bundleGenerator.Generate()
	if err != nil {
		return "", fmt.Errorf("generate debug bundle: %w", err)
	}
	defer func() {
		if err := os.Remove(path); err != nil {
			log.Errorf("failed to remove debug bundle file: %v", err)
		}
	}()

	key, err := debug.UploadDebugBundle(ctx, uploadURL, mgmURL, path, false)
	if err != nil {
		log.Errorf("failed to upload debug bundle: %v", err)
		return "", fmt.Errorf("upload debug bundle: %w", err)
	}

	log.Infof("debug bundle has been generated successfully")
	return key, nil
}

// requireExplicitDebugUploadURL prevents a remote management job from
// silently transmitting diagnostic bundles to the inherited NetBird cloud.
// An explicit HTTPS endpoint is required before even generating a bundle.
func requireExplicitDebugUploadURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("remote debug bundle upload requires an explicitly configured HTTPS endpoint")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || strings.Contains(raw, "#") {
		return fmt.Errorf("remote debug bundle upload requires a valid HTTPS endpoint without credentials or fragments")
	}
	host := strings.ToLower(parsed.Hostname())
	for _, upstream := range []string{"netbird.io", "wiretrustee.com", "netbird.cloud"} {
		if host == upstream || strings.HasSuffix(host, "."+upstream) {
			return fmt.Errorf("inherited upstream diagnostic upload host is not permitted")
		}
	}
	return nil
}

func waitFor(ctx context.Context, duration time.Duration) error {
	log.Infof("wait for %v minutes before executing debug bundle", duration.Minutes())
	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		log.Infof("wait cancelled: %v", ctx.Err())
		return ctx.Err()
	}
}
