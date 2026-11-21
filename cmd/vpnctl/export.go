package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/GoreeCloud/VPN/internal/control"
	"github.com/GoreeCloud/VPN/internal/wireguard"
)

// A gateway export is a registry snapshot, NOT proof of packet enforcement.
type registeredPeer struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	PublicKey  string     `json:"public_key"`
	Address    string     `json:"address"`
	CreatedAt  time.Time  `json:"created_at"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

var peerIDPattern = regexp.MustCompile("^[0-9a-f]{32}$")
var allowedSubnet = netip.MustParsePrefix("10.77.0.0/24")

func activePeerSnapshot(source []byte) ([]byte, error) {
	if len(source) == 0 || len(source) > 1024*1024 {
		return nil, errors.New("invalid peer snapshot size")
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	var response struct {
		Peers []registeredPeer `json:"peers"`
	}
	if err := decoder.Decode(&response); err != nil {
		return nil, errors.New("invalid peer snapshot")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected peer snapshot trailing data")
	}
	if len(response.Peers) > 253 {
		return nil, errors.New("peer inventory too large")
	}
	peers := make([]wireguard.GatewayPeer, 0, len(response.Peers))
	seenID := map[string]bool{}
	seenAddress := map[string]bool{}
	seenKey := map[string]bool{}
	for _, p := range response.Peers {
		prefix, err := netip.ParsePrefix(p.Address)
		if !peerIDPattern.MatchString(p.ID) || p.Name == "" ||
			p.CreatedAt.IsZero() || !control.ValidPublicKey(p.PublicKey) ||
			err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 ||
			!allowedSubnet.Contains(prefix.Addr()) ||
			prefix.Addr().As4()[3] < 2 || prefix.Addr().As4()[3] > 254 ||
			seenID[p.ID] || seenKey[p.PublicKey] || seenAddress[p.Address] {
			return nil, errors.New("peer snapshot contains invalid or duplicate identities")
		}
		seenID[p.ID], seenAddress[p.Address], seenKey[p.PublicKey] = true, true, true
		if p.RevokedAt == nil && p.ApprovedAt != nil {
			peers = append(peers, wireguard.GatewayPeer{PublicKey: p.PublicKey, Address: p.Address})
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Address < peers[j].Address })
	result, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(result, '\n'), nil
}

func writePeerSnapshot(destination string, payload []byte) error {
	if !filepath.IsAbs(destination) {
		return errors.New("gateway snapshot output must be an absolute path")
	}
	parent, err := os.Lstat(filepath.Dir(destination))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0077 != 0 {
		return errors.New("gateway snapshot output parent must be a private real directory")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(payload); err != nil {
		_ = file.Close()
		_ = os.Remove(destination)
		return fmt.Errorf("could not save gateway snapshot: %w", err)
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(destination)
		return err
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}
