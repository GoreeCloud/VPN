package wireguard

import (
    "crypto/ecdh"
    "encoding/base64"
    "errors"
    "fmt"
    "net/netip"
    "sort"
    "strings"
)

// GatewayPeer describes a single explicit WireGuard peer on a development
// gateway. No all-to-all policy, runtime firewall changes or gateway deployment.
type GatewayPeer struct {
    PublicKey string `json:"public_key"`
    Address string `json:"address"`
}

type GatewayOptions struct {
    PrivateKey string
    ListenPort int
    Peers []GatewayPeer
}

func RenderGatewayConfig(options GatewayOptions)([]byte,error){
    if options.ListenPort<1 || options.ListenPort>65535{
        return nil,errors.New("gateway UDP port out of range")
    }
    keyRaw,err:=validKey(options.PrivateKey)
    if err!=nil{return nil,errors.New("invalid gateway private key")}
    private,err:=ecdh.X25519().NewPrivateKey(keyRaw)
    if err!=nil{return nil,errors.New("invalid gateway private key")}
    ownPublic:=base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
    if len(options.Peers)>252{return nil,errors.New("too many peers for development address pool")}
    peers:=append([]GatewayPeer(nil),options.Peers...)
    seenAddr:=map[string]bool{}
    seenKey:=map[string]bool{}
    for _,p:=range peers {
        keyBytes,err:=validKey(p.PublicKey)
        if err!=nil{return nil,errors.New("invalid peer public key")}
        var nonzero byte
        for _,b:=range keyBytes {nonzero|=b}
        if nonzero==0 || p.PublicKey==ownPublic {
            return nil,errors.New("invalid or gateway-equal peer key")
        }
        if _,err:=ecdh.X25519().NewPublicKey(keyBytes);err!=nil{return nil,err}
        ip,err:=netip.ParsePrefix(p.Address)
        if err!=nil || !ip.Addr().Is4() || ip.Bits()!=32 || !devNetwork.Contains(ip.Addr()) {
            return nil,errors.New("peer must have an assigned 10.77.0.x/32")
        }
        a:=ip.Addr().As4()
        if a[3]<2 || a[3]>254{return nil,errors.New("reserved gateway/network/broadcast address")}
        if seenKey[p.PublicKey] || seenAddr[p.Address] {
            return nil,errors.New("duplicate gateway peer identity or address")
        }
        seenKey[p.PublicKey],seenAddr[p.Address]=true,true
    }
    sort.Slice(peers,func(i,j int)bool{return peers[i].Address<peers[j].Address})
    var b strings.Builder
    b.WriteString(fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.77.0.1/24\nListenPort = %d\n",options.PrivateKey,options.ListenPort))
    for _,p:=range peers {
        b.WriteString(fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n",p.PublicKey,p.Address))
    }
    return []byte(b.String()),nil
}
