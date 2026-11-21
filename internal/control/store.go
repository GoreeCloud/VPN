// Package control provides the first-party GoreeCloud VPN peer registry.
// It does not configure a WireGuard interface or claim an active encrypted tunnel.
package control

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"
)

var (
	ErrDuplicate = errors.New("peer public key already registered")
	ErrNotFound  = errors.New("peer not found")
	ErrRevoked   = errors.New("peer already revoked")
	ErrApproved  = errors.New("peer already approved")
	ErrFull      = errors.New("peer address pool exhausted")
	ErrInvalid   = errors.New("invalid peer name or WireGuard public key")
	ErrLocked    = errors.New("peer registry already owned by another process")
	ErrClosed    = errors.New("peer registry closed")
)

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// Peer is public control-plane metadata, NEVER a WireGuard private key.
type Peer struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	PublicKey  string     `json:"public_key"`
	Address    string     `json:"address"`
	CreatedAt  time.Time  `json:"created_at"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type persisted struct {
	Version int    `json:"version"`
	Peers   []Peer `json:"peers"`
}

type Store struct {
	mu    sync.Mutex
	dir   string
	lock  *os.File
	state persisted
}

// An advisory lock prevents two control-plane instances from overwriting one
// another's atomically renamed state. The lock has no sensitive contents.
func stateLock(dir string) (*os.File, error) {
	path := filepath.Join(dir, "state.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open private state lock: %w", err)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 0 {
		_ = f.Close()
		return nil, errors.New("unsafe state lock file")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, ErrLocked
	}
	return f, nil
}

// Close releases process ownership of the registry. Call only after its
// HTTP server has stopped; concurrent use after Close is rejected.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	closeErr := s.lock.Close()
	s.lock = nil
	if err != nil {
		return err
	}
	return closeErr
}

func validStoredPeer(p Peer) bool {
	if len(p.ID) != 32 || len(p.PublicKey) != 44 || !validName.MatchString(p.Name) ||
		!ValidPublicKey(p.PublicKey) || p.CreatedAt.IsZero() {
		return false
	}
	for _, ch := range p.ID {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	ip, err := netip.ParsePrefix(p.Address)
	if err != nil || !ip.Addr().Is4() || ip.Bits() != 32 || !ip.IsValid() {
		return false
	}
	if !netip.MustParsePrefix("10.77.0.0/24").Contains(ip.Addr()) {
		return false
	}
	a := ip.Addr().As4()
	if a[3] < 2 || a[3] > 254 {
		return false
	}
	if p.ApprovedAt != nil && p.ApprovedAt.Before(p.CreatedAt) {
		return false
	}
	if p.RevokedAt != nil && p.RevokedAt.Before(p.CreatedAt) {
		return false
	}
	if p.ApprovedAt != nil && p.RevokedAt != nil && p.ApprovedAt.After(*p.RevokedAt) {
		return false
	}
	return true
}

func Open(dir string) (result *Store, openErr error) {
	if dir == "" {
		return nil, errors.New("missing state directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("make private state directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be a non-symlink private directory (0700)")
	}
	lock, err := stateLock(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if openErr != nil {
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			_ = lock.Close()
		}
	}()
	s := &Store{dir: dir, lock: lock, state: persisted{Version: 1, Peers: []Peer{}}}
	file := filepath.Join(dir, "state.json")
	fi, err := os.Lstat(file)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 || fi.Size() > 2<<20 {
		return nil, errors.New("unsafe or oversized state file")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.state); err != nil {
		return nil, fmt.Errorf("invalid stored state: %w", err)
	}
	if err := validatePersisted(s.state); err != nil {
		return nil, err
	}
	if s.state.Peers == nil {
		s.state.Peers = []Peer{}
	}
	return s, nil
}

// ValidateSnapshotJSON authenticates registry *structure*, never device
// authorization. It is used for safe encrypted backup and staged restore.
func ValidateSnapshotJSON(data []byte) error {
	if len(data) == 0 || len(data) > 2<<20 {
		return errors.New("invalid registry snapshot size")
	}
	var snapshot persisted
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return errors.New("invalid registry snapshot JSON")
	}
	return validatePersisted(snapshot)
}
func validatePersisted(snapshot persisted) error {
	if snapshot.Version != 1 {
		return errors.New("unsupported registry schema version")
	}
	if len(snapshot.Peers) > 253 {
		return errors.New("registry peer address limit exceeded")
	}
	seenID, seenAddress, seenKey := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range snapshot.Peers {
		if !validStoredPeer(p) || seenID[p.ID] || seenAddress[p.Address] || seenKey[p.PublicKey] {
			return errors.New("inconsistent stored peer registry")
		}
		seenID[p.ID], seenAddress[p.Address], seenKey[p.PublicKey] = true, true, true
	}
	return nil
}

func ValidPublicKey(v string) bool {
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != v {
		return false
	}
	var nonzero byte
	for _, b := range raw {
		nonzero |= b
	}
	if nonzero == 0 {
		return false
	}
	_, err = ecdh.X25519().NewPublicKey(raw)
	return err == nil
}

func (s *Store) List() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Peer(nil), s.state.Peers...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID)
	})
	return out
}

func (s *Store) Add(name, publicKey string) (Peer, error) {
	if !validName.MatchString(name) || !ValidPublicKey(publicKey) {
		return Peer{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return Peer{}, ErrClosed
	}
	used := make(map[string]bool)
	for _, p := range s.state.Peers {
		if p.PublicKey == publicKey {
			return Peer{}, ErrDuplicate
		}
		used[p.Address] = true
	}
	address := ""
	for n := 2; n <= 254; n++ {
		candidate := fmt.Sprintf("10.77.0.%d/32", n)
		if !used[candidate] {
			address = candidate
			break
		}
	}
	if address == "" {
		return Peer{}, ErrFull
	}
	buf := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return Peer{}, err
	}
	p := Peer{ID: hex.EncodeToString(buf), Name: name, PublicKey: publicKey, Address: address, CreatedAt: time.Now().UTC()}
	next := persisted{Version: 1, Peers: append(append([]Peer(nil), s.state.Peers...), p)}
	if err := s.save(next); err != nil {
		return Peer{}, err
	}
	s.state = next
	return p, nil
}

// Approve explicitly authorizes a registered public key for subsequent gateway
// export. It does not itself install a WireGuard peer or grant live packet access.
func (s *Store) Approve(id string) (Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return Peer{}, ErrClosed
	}
	peers := append([]Peer(nil), s.state.Peers...)
	for i := range peers {
		if peers[i].ID != id {
			continue
		}
		if peers[i].RevokedAt != nil {
			return Peer{}, ErrRevoked
		}
		if peers[i].ApprovedAt != nil {
			return Peer{}, ErrApproved
		}
		now := time.Now().UTC()
		peers[i].ApprovedAt = &now
		next := persisted{Version: 1, Peers: peers}
		if err := s.save(next); err != nil {
			return Peer{}, err
		}
		s.state = next
		return peers[i], nil
	}
	return Peer{}, ErrNotFound
}

func (s *Store) Revoke(id string) (Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return Peer{}, ErrClosed
	}
	peers := append([]Peer(nil), s.state.Peers...)
	for i := range peers {
		if peers[i].ID != id {
			continue
		}
		if peers[i].RevokedAt != nil {
			return Peer{}, ErrRevoked
		}
		now := time.Now().UTC()
		peers[i].RevokedAt = &now
		next := persisted{Version: 1, Peers: peers}
		if err := s.save(next); err != nil {
			return Peer{}, err
		}
		s.state = next
		return peers[i], nil
	}
	return Peer{}, ErrNotFound
}

func (s *Store) save(next persisted) error {
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return errors.New("state file exceeded safety limit")
	}
	f, err := os.CreateTemp(s.dir, ".state-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, "state.json")); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
