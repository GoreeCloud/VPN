// vpnctl is the first-party GoreeCloud VPN control-plane CLI.
// It never reads NetBird credentials or claims that a tunnel is active.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/GoreeCloud/VPN/internal/credentials"
	"github.com/GoreeCloud/VPN/internal/wireguard"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func defaultTokenPath() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "admin-token"
	}
	return filepath.Join(h, ".config/goreecloud/vpn/admin-token")
}

func validateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path != "" || u.Host == "" {
		return nil, errors.New("API URL must be a bare origin with no credentials or path")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	hostname := u.Hostname()
	if u.Scheme == "http" && (hostname == "localhost" || (net.ParseIP(hostname) != nil && net.ParseIP(hostname).IsLoopback())) {
		return u, nil
	}
	return nil, errors.New("remote API requires HTTPS; plaintext allowed on loopback only")
}

func request(method, base, token, path string, payload interface{}) ([]byte, error) {
	u, err := validateURL(base)
	if err != nil {
		return nil, err
	}
	u.Path = path
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Never send an admin bearer token through inherited HTTP(S)_PROXY settings.
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, DisableKeepAlives: true}
	client := &http.Client{Timeout: 12 * time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("API redirect refused") }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("API request failed; verify TLS and control-plane availability")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, errors.New("API response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}
	return b, nil
}

func localKeygen(dir string) error {
	if dir == "" {
		return errors.New("missing --dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	stat, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm()&0077 != 0 {
		return errors.New("key directory must be a real private 0700 directory")
	}
	priv := filepath.Join(dir, "wg-private.key")
	pub := filepath.Join(dir, "wg-public.key")
	if _, err := os.Lstat(priv); err == nil {
		return errors.New("private key already exists; refusing overwrite")
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(pub); err == nil {
		return errors.New("public key already exists; refusing overwrite")
	} else if !os.IsNotExist(err) {
		return err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	raw := base64.StdEncoding.EncodeToString(key.Bytes()) + "\n"
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) + "\n"
	fd, err := os.OpenFile(priv, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := fd.WriteString(raw); err != nil {
		fd.Close()
		os.Remove(priv)
		return err
	}
	if err := fd.Sync(); err != nil {
		fd.Close()
		os.Remove(priv)
		return err
	}
	if err := fd.Close(); err != nil {
		os.Remove(priv)
		return err
	}
	f, err := os.OpenFile(pub, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		os.Remove(priv)
		return err
	}
	if _, err := f.WriteString(public); err != nil {
		f.Close()
		os.Remove(pub)
		os.Remove(priv)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(pub)
		os.Remove(priv)
		return err
	}
	fmt.Println("WireGuard-compatible X25519 keys saved privately. Public key:")
	fmt.Println(strings.TrimSpace(public))
	fmt.Println("No tunnel configured or activated.")
	return nil
}

func writeClientConfiguration(dir, gatewayFile, address, endpoint, output string) error {
	if dir == "" || gatewayFile == "" || address == "" || endpoint == "" || output == "" {
		return errors.New("config-client requires --dir, --gateway-public-key-file, --address, --endpoint and --output")
	}
	privatePath := filepath.Join(dir, "wg-private.key")
	info, err := os.Lstat(privatePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("private key input must be regular mode 0600")
	}
	raw, err := os.ReadFile(privatePath)
	if err != nil {
		return err
	}
	gateway, err := os.ReadFile(gatewayFile)
	if err != nil {
		return err
	}
	body, err := wireguard.RenderClientConfig(wireguard.ClientOptions{
		PrivateKey: strings.TrimSpace(string(raw)), Address: address,
		GatewayPublicKey: strings.TrimSpace(string(gateway)), Endpoint: endpoint,
	})
	if err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(output))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0077 != 0 {
		return errors.New("configuration output parent directory must be private (0700)")
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err != nil {
		f.Close()
		os.Remove(output)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(output)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(output)
		return err
	}
	fmt.Println("Private split-tunnel WireGuard client configuration created (0600). Not installed or activated.")
	return nil
}

func writeGatewayConfiguration(dir, peersFile, output string, port int) error {
	if dir == "" || peersFile == "" || output == "" {
		return errors.New("config-gateway needs --dir, --peers-file and --output")
	}
	keyFile := filepath.Join(dir, "wg-private.key")
	keyInfo, err := os.Lstat(keyFile)
	if err != nil {
		return err
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm() != 0600 || keyInfo.Size() > 256 {
		return errors.New("gateway private key file must be regular mode 0600")
	}
	pinfo, err := os.Lstat(peersFile)
	if err != nil {
		return err
	}
	if !pinfo.Mode().IsRegular() || pinfo.Mode().Perm()&0077 != 0 || pinfo.Size() > 64*1024 {
		return errors.New("peer metadata must be a private regular file <=64KiB")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	peerJSON, err := os.ReadFile(peersFile)
	if err != nil {
		return err
	}
	var peers []wireguard.GatewayPeer
	dec := json.NewDecoder(bytes.NewReader(peerJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&peers); err != nil {
		return errors.New("invalid gateway peers JSON")
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected JSON trailing data")
	}
	body, err := wireguard.RenderGatewayConfig(wireguard.GatewayOptions{
		PrivateKey: strings.TrimSpace(string(raw)), ListenPort: port, Peers: peers,
	})
	if err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(output))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0077 != 0 {
		return errors.New("output parent must be private real directory 0700")
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(body); err != nil {
		file.Close()
		os.Remove(output)
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		os.Remove(output)
		return err
	}
	if err = file.Close(); err != nil {
		os.Remove(output)
		return err
	}
	fmt.Println("Private development WireGuard gateway config created (0600). Gateway NOT activated.")
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: vpnctl init-admin | keygen | config-client | config-gateway | config-acl | export-peers | list | register | approve | revoke | info")
		os.Exit(2)
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	tokenFile := flags.String("token-file", defaultTokenPath(), "owner-private administrator token file")
	origin := flags.String("api", "http://127.0.0.1:8788", "HTTPS remote or loopback control plane")
	dir := flags.String("dir", "", "new private directory for local WireGuard keys")
	name := flags.String("name", "", "peer display name")
	pubFile := flags.String("public-key-file", "", "local public key file")
	id := flags.String("id", "", "peer ID")
	confirm := flags.Bool("confirm", false, "confirm a peer registration, revocation or secret configuration export")
	gatewayKeyFile := flags.String("gateway-public-key-file", "", "local gateway public key file")
	address := flags.String("address", "", "assigned private peer IPv4 /32")
	endpoint := flags.String("endpoint", "", "reviewed gateway host:port")
	output := flags.String("output", "", "new private 0600 configuration path")
	peersFile := flags.String("peers-file", "", "private JSON array of explicit gateway peer public keys and /32s")
	rulesFile := flags.String("rules-file", "", "private JSON array of gateway-local ACL permissions")
	listenPort := flags.Int("listen-port", 51820, "WireGuard gateway UDP listener")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	var err error
	switch command {
	case "init-admin":
		err = credentials.Create(*tokenFile)
		if err == nil {
			fmt.Println("Private administrator token created (0600). Token contents not displayed.")
		}
	case "keygen":
		err = localKeygen(*dir)
	case "config-client":
		if !*confirm {
			err = errors.New("client configuration export requires --confirm")
			break
		}
		err = writeClientConfiguration(*dir, *gatewayKeyFile, *address, *endpoint, *output)
	case "config-gateway":
		if !*confirm {
			err = errors.New("gateway configuration export requires --confirm")
			break
		}
		err = writeGatewayConfiguration(*dir, *peersFile, *output, *listenPort)
	case "config-acl":
		if !*confirm {
			err = errors.New("ACL export requires --confirm after independent peer and service review")
			break
		}
		err = writeGatewayAccessPolicy(*peersFile, *rulesFile, *output)
	case "list", "register", "approve", "revoke", "info", "export-peers":
		var token string
		token, err = credentials.Read(*tokenFile)
		if err != nil {
			break
		}
		var res []byte
		switch command {
		case "list":
			res, err = request("GET", *origin, token, "/v1/peers", nil)
		case "info":
			res, err = request("GET", *origin, token, "/v1/info", nil)
		case "register":
			if !*confirm {
				err = errors.New("registration requires --confirm")
				break
			}
			if *pubFile == "" {
				err = errors.New("required --public-key-file")
				break
			}
			var raw []byte
			raw, err = os.ReadFile(*pubFile)
			if err != nil {
				break
			}
			res, err = request("POST", *origin, token, "/v1/peers", map[string]string{"name": *name, "public_key": strings.TrimSpace(string(raw))})
		case "export-peers":
			if !*confirm || *output == "" {
				err = errors.New("export-peers requires --output and --confirm; config is not automatically applied")
				break
			}
			res, err = request("GET", *origin, token, "/v1/peers", nil)
			if err != nil {
				break
			}
			var snapshot []byte
			snapshot, err = activePeerSnapshot(res)
			if err != nil {
				break
			}
			err = writePeerSnapshot(*output, snapshot)
			if err == nil {
				fmt.Println("Private current-state gateway peer snapshot exported (0600). Revoked identities excluded. NOT APPLIED to a gateway.")
				res = nil
			}
		case "approve":
			if !*confirm || len(*id) != 32 || strings.Trim(*id, "0123456789abcdef") != "" {
				err = errors.New("approve requires --id (32 lowercase hex characters) and --confirm")
				break
			}
			res, err = request("POST", *origin, token, "/v1/peers/"+*id+"/approve", nil)
		case "revoke":
			if !*confirm || len(*id) != 32 || strings.Trim(*id, "0123456789abcdef") != "" {
				err = errors.New("revoke requires --id (32 lowercase hex characters) and --confirm")
				break
			}
			res, err = request("POST", *origin, token, "/v1/peers/"+*id+"/revoke", nil)
		}
		if err == nil && len(res) > 0 {
			var value interface{}
			if err = json.Unmarshal(res, &value); err == nil {
				pretty, e := json.MarshalIndent(value, "", "  ")
				if e == nil {
					fmt.Println(string(pretty))
				}
			}
		}
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
}
