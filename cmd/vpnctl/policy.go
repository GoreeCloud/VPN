package main

// Offline gateway service ACL generator. This command does not invoke nft,
// require root, modify the network, or grant access before explicit gateway apply.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/GoreeCloud/VPN/internal/policy"
	"github.com/GoreeCloud/VPN/internal/wireguard"
)

func readPrivatePolicyInput(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("policy input requires an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64*1024 || info.Size() == 0 {
		return nil, errors.New("policy input must be an owner-private regular file <=64KiB")
	}
	return os.ReadFile(path)
}
func strictJSONArray(data []byte, destination any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(destination); err != nil {
		return errors.New("invalid ACL JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected ACL JSON trailing content")
	}
	return nil
}
func writeGatewayAccessPolicy(peersFile, rulesFile, output string) error {
	if peersFile == "" || rulesFile == "" || output == "" {
		return errors.New("config-acl needs --peers-file, --rules-file and --output")
	}
	peersJSON, err := readPrivatePolicyInput(peersFile)
	if err != nil {
		return err
	}
	ruleJSON, err := readPrivatePolicyInput(rulesFile)
	if err != nil {
		return err
	}
	var peers []wireguard.GatewayPeer
	if err = strictJSONArray(peersJSON, &peers); err != nil {
		return err
	}
	var rules []policy.Rule
	if err = strictJSONArray(ruleJSON, &rules); err != nil {
		return err
	}
	body, err := policy.RenderGatewayFirewall(peers, rules)
	if err != nil {
		return err
	}
	if err = writePeerSnapshot(output, body); err != nil {
		return err
	}
	fmt.Println("Default-deny gateway-local nftables ACL rendered (0600). NOT APPLIED. Review host policy and rollback before installation.")
	return nil
}
