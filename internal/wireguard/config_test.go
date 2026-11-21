package wireguard

import (
    "crypto/ecdh"
    "crypto/rand"
    "encoding/base64"
    "strings"
    "testing"
)

func key(t *testing.T)(string,string){
    t.Helper()
    p,e:=ecdh.X25519().GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
    return base64.StdEncoding.EncodeToString(p.Bytes()),base64.StdEncoding.EncodeToString(p.PublicKey().Bytes())
}

func TestClientConfigRestrictedAndDeterministic(t *testing.T){
    priv,_:=key(t)
    _,gateway:=key(t)
    b,err:=RenderClientConfig(ClientOptions{PrivateKey:priv,Address:"10.77.0.2/32",GatewayPublicKey:gateway,Endpoint:"vpn.example.org:51820"})
    if err!=nil{t.Fatal(err)}
    s:=string(b)
    for _,v:=range []string{"[Interface]","PrivateKey = "+priv,"Address = 10.77.0.2/32","[Peer]","PublicKey = "+gateway,"AllowedIPs = 10.77.0.0/24","PersistentKeepalive = 25"}{
        if !strings.Contains(s,v){t.Fatal("missing expected configuration field")}
    }
    if strings.Contains(s,"0.0.0.0/0"){t.Fatal("accidentally full tunneling")}
}
func TestClientConfigRejectsUnsafeInput(t *testing.T){
    priv,pub:=key(t)
    _,gateway:=key(t)
    base:=ClientOptions{PrivateKey:priv,Address:"10.77.0.2/32",GatewayPublicKey:gateway,Endpoint:"vpn.example.org:51820"}
    bad:=[]ClientOptions{}
    x:=base;x.Address="0.0.0.0/0";bad=append(bad,x)
    x=base;x.Address="10.77.0.1/32";bad=append(bad,x)
    x=base;x.Address="10.77.0.254/24";bad=append(bad,x)
    x=base;x.Endpoint="vpn.example.org:0";bad=append(bad,x)
    x=base;x.Endpoint="vpn.example.org:51820\nPostUp = /bin/sh";bad=append(bad,x)
    x=base;x.Endpoint="0.0.0.0:51820";bad=append(bad,x)
    x=base;x.GatewayPublicKey=pub;bad=append(bad,x)
    x=base;x.PrivateKey="not-a-key";bad=append(bad,x)
    for _,opt:=range bad{
        if _,err:=RenderClientConfig(opt);err==nil{t.Fatalf("accepted unsafe input %+v",opt.Address)}
    }
}
