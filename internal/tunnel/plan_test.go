package tunnel

import (
    "crypto/ecdh"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func testKeys(t *testing.T)(string,string,string){
    t.Helper()
    client,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    gateway,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    dir:=t.TempDir()
    file:=filepath.Join(dir,"device.private")
    if err:=os.WriteFile(file,[]byte(base64.StdEncoding.EncodeToString(client.Bytes())+"\n"),0600);err!=nil{t.Fatal(err)}
    return file,base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()),base64.StdEncoding.EncodeToString(gateway.PublicKey().Bytes())
}
func TestPlanNeverEmbedsPrivateKey(t *testing.T){
    file,_,pub:=testKeys(t)
    cfg:=Settings{PrivateKeyFile:file,GatewayPublicKey:pub,ClientAddress:"10.77.0.2/32",Endpoint:"vpn.example.test:51820"}
    steps,err:=Plan(cfg);if err!=nil{t.Fatal(err)}
    if len(steps)!=5{t.Fatalf("invalid operation steps %v",len(steps))}
    raw,err:=os.ReadFile(file);if err!=nil{t.Fatal(err)}
    for _,cmd:=range steps{
        if strings.Contains(cmd.String(),strings.TrimSpace(string(raw))){t.Fatal("secret exposed on process argv")}
        if strings.Contains(cmd.String(),"0.0.0.0/0"){t.Fatal("unsafe default-route hijack")}
        if strings.Contains(cmd.String(),"netbird"){t.Fatal("NetBird tooling mixed with first-party operations")}
    }
    calls:=[]string{}
    if err:=Apply(steps,func(n string,args ...string)error{calls=append(calls,n+" "+strings.Join(args," "));return nil});err!=nil{t.Fatal(err)}
    if len(calls)!=5{t.Fatal("not all isolated steps executed")}
}
func TestPlanRejectsUnsafeInputs(t *testing.T){
    file,clientPub,serverPub:=testKeys(t)
    base:=Settings{PrivateKeyFile:file,GatewayPublicKey:serverPub,ClientAddress:"10.77.0.2/32",Endpoint:"vpn.example.test:51820"}
    cases:=[]Settings{}
    x:=base;x.ClientAddress="0.0.0.0/0";cases=append(cases,x)
    x=base;x.ClientAddress="100.73.60.182/32";cases=append(cases,x)
    x=base;x.GatewayPublicKey=clientPub;cases=append(cases,x)
    x=base;x.Endpoint="vpn.example.test:51820\nPostUp=evil";cases=append(cases,x)
    x=base;x.PrivateKeyFile="relative.key";cases=append(cases,x)
    x=base;x.Endpoint="127.0.0.1:0";cases=append(cases,x)
    for _,input:=range cases{if _,err:=Plan(input);err==nil{t.Fatalf("unsafe input allowed: %+v",input.ClientAddress)}}
    if err:=os.Chmod(file,0644);err!=nil{t.Fatal(err)}
    if _,err:=Plan(base);err==nil{t.Fatal("insecure private key file accepted")}
}
func TestApplyRollbackAfterPartialFailure(t *testing.T){
    file,_,pub:=testKeys(t)
    steps,err:=Plan(Settings{PrivateKeyFile:file,GatewayPublicKey:pub,ClientAddress:"10.77.0.2/32",Endpoint:"vpn.example.test:51820"});if err!=nil{t.Fatal(err)}
    calls:=[]string{}
    failAt:=3
    runner:=func(n string,args ...string)error{
        calls=append(calls,n+" "+strings.Join(args," "))
        if len(calls)==failAt{return errors.New("injected data-plane error")}
        return nil
    }
    if err:=Apply(steps,runner);err==nil{t.Fatal("expected injected command failure")}
    if len(calls)!=4 || calls[3]!="ip link delete dev gcvpn0"{t.Fatalf("rollback not executed: %v",calls)}
}
