package wireguard

import (
    "strings"
    "testing"
)

func TestGatewayConfigAssignsPeer32Only(t *testing.T){
    priv,_:=key(t)
    _,p1:=key(t)
    _,p2:=key(t)
    cfg:=GatewayOptions{PrivateKey:priv,ListenPort:51820,Peers:[]GatewayPeer{
        {PublicKey:p2,Address:"10.77.0.20/32"},
        {PublicKey:p1,Address:"10.77.0.2/32"},
    }}
    bytes,err:=RenderGatewayConfig(cfg);if err!=nil{t.Fatal(err)}
    text:=string(bytes)
    if !strings.Contains(text,"Address = 10.77.0.1/24") || !strings.Contains(text,"ListenPort = 51820"){
        t.Fatal("gateway address or listener missing")
    }
    if !strings.Contains(text,"AllowedIPs = 10.77.0.2/32")||!strings.Contains(text,"AllowedIPs = 10.77.0.20/32"){
        t.Fatal("peer-specific allowed IPs absent")
    }
    if strings.Contains(text,"0.0.0.0/0"){t.Fatal("unexpected broad tunnel allowed")}
    if strings.Index(text,"10.77.0.2/32")>strings.Index(text,"10.77.0.20/32"){t.Fatal("non-deterministic peer ordering")}
}

func TestGatewayDeniesUnsafePeers(t *testing.T){
    gatewayPrivate,gatewayPub:=key(t)
    _,public:=key(t)
    base:=GatewayOptions{PrivateKey:gatewayPrivate,ListenPort:51820,Peers:[]GatewayPeer{{PublicKey:public,Address:"10.77.0.2/32"}}}
    bad:=[]GatewayOptions{}
    x:=base;x.ListenPort=0;bad=append(bad,x)
    x=base;x.PrivateKey="invalid";bad=append(bad,x)
    x=base;x.Peers=[]GatewayPeer{{PublicKey:gatewayPub,Address:"10.77.0.2/32"}};bad=append(bad,x)
    x=base;x.Peers=[]GatewayPeer{{PublicKey:public,Address:"0.0.0.0/0"}};bad=append(bad,x)
    x=base;x.Peers=[]GatewayPeer{{PublicKey:public,Address:"10.77.0.1/32"}};bad=append(bad,x)
    x=base;x.Peers=[]GatewayPeer{{PublicKey:public,Address:"10.77.0.255/32"}};bad=append(bad,x)
    x=base;x.Peers=[]GatewayPeer{{PublicKey:public,Address:"10.77.0.2/32"},{PublicKey:public,Address:"10.77.0.3/32"}};bad=append(bad,x)
    for _,opt:=range bad{
        if _,err:=RenderGatewayConfig(opt);err==nil{t.Fatal("accepted unsafe gateway peer config")}
    }
}
