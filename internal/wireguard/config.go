// Package wireguard renders conservative WireGuard client configuration.
// It never installs a tunnel, executes wg, or sends a private key over a network.
package wireguard

import (
    "crypto/ecdh"
    "encoding/base64"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "regexp"
    "strconv"
)

type ClientOptions struct {
    PrivateKey string
    Address string
    GatewayPublicKey string
    Endpoint string
}

var domain = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
var devNetwork = netip.MustParsePrefix("10.77.0.0/24")

func validKey(text string)([]byte,error){
    raw,err:=base64.StdEncoding.DecodeString(text)
    if err!=nil || len(raw)!=32 || base64.StdEncoding.EncodeToString(raw)!=text {
        return nil,errors.New("invalid WireGuard key: expected canonical base64 of 32 bytes")
    }
    return raw,nil
}

// RenderClientConfig deliberately restricts AllowedIPs to the product's
// development-only split-tunnel prefix, never a default/full-tunnel route.
func RenderClientConfig(options ClientOptions)([]byte,error){
    private,err:=validKey(options.PrivateKey);if err!=nil{return nil,errors.New("invalid client private key")}
    key,err:=ecdh.X25519().NewPrivateKey(private)
    if err!=nil{return nil,errors.New("invalid client private key")}
    gateway,err:=validKey(options.GatewayPublicKey)
    if err!=nil{return nil,errors.New("invalid gateway public key")}
    if _,err:=ecdh.X25519().NewPublicKey(gateway);err!=nil{return nil,errors.New("invalid gateway public key")}
    if base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())==options.GatewayPublicKey {
        return nil,errors.New("client and gateway keys must differ")
    }
    ip,err:=netip.ParsePrefix(options.Address)
    if err!=nil || !ip.Addr().Is4() || ip.Bits()!=32 || !devNetwork.Contains(ip.Addr()) ||
        ip.Addr()==netip.MustParseAddr("10.77.0.1") || ip.Addr()==netip.MustParseAddr("10.77.0.0") ||
        ip.Addr()==netip.MustParseAddr("10.77.0.255") {
        return nil,errors.New("client address must be a valid reserved 10.77.0.0/24 /32")
    }
    host,portText,err:=net.SplitHostPort(options.Endpoint)
    if err!=nil || host=="" || len(host)>253{return nil,errors.New("invalid gateway endpoint")}
    port,err:=strconv.Atoi(portText)
    if err!=nil || port<1 || port>65535{return nil,errors.New("invalid gateway port")}
    if net.ParseIP(host)==nil && !domain.MatchString(host){return nil,errors.New("invalid gateway hostname")}
    if host=="0.0.0.0" || host=="::" {return nil,errors.New("wildcard is not a valid peer gateway")}
    result:=fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 10.77.0.0/24\nPersistentKeepalive = 25\n",
        options.PrivateKey,ip.String(),options.GatewayPublicKey,options.Endpoint)
    return []byte(result),nil
}
