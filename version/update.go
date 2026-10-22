package version

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
)

const (
	fetchPeriod        = 30 * time.Minute
	fetchTimeout       = 10 * time.Second
	maxVersionResponse = 100
	// No GoreeCloud version-discovery channel has been qualified.
	defaultVersionURL = ""
)

var (
	versionURL = defaultVersionURL
)

// Update fetch the version info periodically and notify the onUpdateListener in case the UI version or the
// daemon version are deprecated
type Update struct {
	httpAgent       string
	uiVersion       *goversion.Version
	daemonVersion   *goversion.Version
	latestAvailable *goversion.Version
	versionsLock    sync.Mutex

	versionURL   string // immutable after construction
	fetchMu      sync.Mutex
	fetchCancel  context.CancelFunc
	fetchDone    chan struct{}
	fetchStopped bool

	onUpdateListener func()
	listenerLock     sync.Mutex
}

// NewUpdate instantiate Update and start to fetch the new version information
func NewUpdate(httpAgent string) *Update {
	currentVersion, err := goversion.NewVersion(version)
	if err != nil {
		currentVersion, _ = goversion.NewVersion("0.0.0")
	}

	u := &Update{
		httpAgent:  httpAgent,
		uiVersion:  currentVersion,
		versionURL: versionURL,
	}

	return u
}

func NewUpdateAndStart(httpAgent string) *Update {
	u := NewUpdate(httpAgent)
	go u.StartFetcher()

	return u
}

// StopWatch stop the version info fetch loop
func (u *Update) StopWatch() {
	u.fetchMu.Lock()
	u.fetchStopped = true
	cancel, done := u.fetchCancel, u.fetchDone
	u.fetchMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// SetDaemonVersion update the currently running daemon version. If new version is available it will trigger
// the onUpdateListener
func (u *Update) SetDaemonVersion(newVersion string) bool {
	daemonVersion, err := goversion.NewVersion(newVersion)
	if err != nil {
		daemonVersion, _ = goversion.NewVersion("0.0.0")
	}

	u.versionsLock.Lock()
	if u.daemonVersion != nil && u.daemonVersion.Equal(daemonVersion) {
		u.versionsLock.Unlock()
		return false
	}

	u.daemonVersion = daemonVersion
	u.versionsLock.Unlock()
	return u.checkUpdate()
}

// SetOnUpdateListener set new update listener
func (u *Update) SetOnUpdateListener(updateFn func()) {
	u.listenerLock.Lock()
	u.onUpdateListener = updateFn
	u.listenerLock.Unlock()
	// A listener may stop the fetcher. Do not hold the listener lock while
	// invoking it, since an in-flight fetch also needs that lock to notify.
	if updateFn != nil && u.isUpdateAvailable() {
		updateFn()
	}
}

func (u *Update) LatestVersion() *goversion.Version {
	u.versionsLock.Lock()
	defer u.versionsLock.Unlock()
	return u.latestAvailable
}

// StartFetcher is single-use. StopWatch also prevents a scheduled start that
// has not acquired the lifecycle lock yet.
func (u *Update) StartFetcher() {
	if u.versionURL == "" {
		return
	}
	u.fetchMu.Lock()
	if u.fetchStopped || u.fetchDone != nil {
		u.fetchMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	u.fetchCancel, u.fetchDone = cancel, done
	u.fetchMu.Unlock()
	defer close(done)
	defer cancel()

	ticker := time.NewTicker(fetchPeriod)
	defer ticker.Stop()
	if changed := u.fetchVersion(ctx); changed {
		u.checkUpdate()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if changed := u.fetchVersion(ctx); changed {
				u.checkUpdate()
			}
		}
	}
}

func (u *Update) fetchVersion(ctx context.Context) bool {
	if u.versionURL == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	log.Debugf("fetching version info from %s", u.versionURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.versionURL, nil)
	if err != nil {
		log.Errorf("failed to create request for version info: %s", err)
		return false
	}

	req.Header.Set("User-Agent", u.httpAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("failed to fetch version info: %s", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("invalid status code: %d", resp.StatusCode)
		return false
	}

	if resp.ContentLength > maxVersionResponse {
		log.Errorf("too large response: %d", resp.ContentLength)
		return false
	}

	content, err := io.ReadAll(io.LimitReader(resp.Body, maxVersionResponse+1))
	if err != nil {
		log.Errorf("failed to read content: %s", err)
		return false
	}

	if len(content) > maxVersionResponse {
		log.Error("version response exceeds size limit")
		return false
	}

	latestAvailable, err := goversion.NewVersion(string(content))
	if err != nil {
		log.Errorf("failed to parse the version string: %s", err)
		return false
	}

	u.versionsLock.Lock()
	defer u.versionsLock.Unlock()

	if u.latestAvailable != nil && u.latestAvailable.Equal(latestAvailable) {
		return false
	}
	u.latestAvailable = latestAvailable

	return true
}

func (u *Update) checkUpdate() bool {
	if !u.isUpdateAvailable() {
		return false
	}

	u.listenerLock.Lock()
	defer u.listenerLock.Unlock()
	if u.onUpdateListener == nil {
		return true
	}

	go u.onUpdateListener()
	return true
}

func (u *Update) isUpdateAvailable() bool {
	u.versionsLock.Lock()
	defer u.versionsLock.Unlock()

	if u.latestAvailable == nil {
		return false
	}

	if u.latestAvailable.GreaterThan(u.uiVersion) {
		return true
	}

	if u.daemonVersion == nil {
		return false
	}

	if u.latestAvailable.GreaterThan(u.daemonVersion) {
		return true
	}
	return false
}
