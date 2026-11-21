package main

import (
 "os"
 "crypto/ecdh"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "strings"
 "path/filepath"
 "testing"
)

func TestURLValidation(t *testing.T){
 for _,u:=range []string{"https://vpn.example.test","http://127.0.0.1:8788","http://localhost:8788","http://[::1]:8788"}{
  if _,err:=validateURL(u);err!=nil{t.Fatalf("valid URL refused %q: %v",u,err)}
 }
 for _,u:=range []string{"http://vpn.example.test","http://192.168.1.2:8788","http://0.0.0.0:8788","https://user:password@vpn.test","https://vpn.test/x","https://vpn.test?token=a","file:///etc/passwd"}{
  if _,err:=validateURL(u);err==nil{t.Fatalf("unsafe URL accepted: %q",u)}
 }
}

func TestKeygenNoOverwrite(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"new")
 if err:=localKeygen(dir);err!=nil{t.Fatal(err)}
 p:=filepath.Join(dir,"wg-private.key")
 if fi,err:=os.Stat(p);err!=nil||fi.Mode().Perm()!=0600{t.Fatalf("unsafe private key %v %v",fi,err)}
 raw,err:=os.ReadFile(p);if err!=nil{t.Fatal(err)}
 if len(raw)<40{t.Fatal("key absent")}
 if err:=localKeygen(dir);err==nil{t.Fatal("recreated private key")}
 after,err:=os.ReadFile(p);if err!=nil{t.Fatal(err)}
 if string(raw)!=string(after){t.Fatal("key overwritten")}
}


func TestPrivateWireGuardConfigExportAndNoOverwrite(t *testing.T){
    dir:=filepath.Join(t.TempDir(),"private")
    if err:=localKeygen(dir);err!=nil{t.Fatal(err)}
    gateway,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    pub:=filepath.Join(dir,"gateway-public.key")
    if err:=os.WriteFile(pub,[]byte(base64.StdEncoding.EncodeToString(gateway.PublicKey().Bytes())+"\n"),0600);err!=nil{t.Fatal(err)}
    output:=filepath.Join(dir,"gc-vpn-client.conf")
    if err:=writeClientConfiguration(dir,pub,"10.77.0.2/32","vpn.example.test:51820",output);err!=nil{t.Fatal(err)}
    info,err:=os.Stat(output);if err!=nil{t.Fatal(err)}
    if info.Mode().Perm()!=0600{t.Fatal("configuration file not private")}
    content,err:=os.ReadFile(output);if err!=nil{t.Fatal(err)}
    if !strings.Contains(string(content),"AllowedIPs = 10.77.0.0/24"){t.Fatal("unsafe route scope")}
    if err:=writeClientConfiguration(dir,pub,"10.77.0.2/32","vpn.example.test:51820",output);err==nil{t.Fatal("overwrote private config")}
}


func TestPrivateGatewayConfigurationExport(t *testing.T){
    gatewayDir:=filepath.Join(t.TempDir(),"gateway")
    clientDir:=filepath.Join(t.TempDir(),"client")
    if err:=localKeygen(gatewayDir);err!=nil{t.Fatal(err)}
    if err:=localKeygen(clientDir);err!=nil{t.Fatal(err)}
    clientKey,err:=os.ReadFile(filepath.Join(clientDir,"wg-public.key"));if err!=nil{t.Fatal(err)}
    peers:=[]map[string]string{{"public_key":strings.TrimSpace(string(clientKey)),"address":"10.77.0.2/32"}}
    payload,err:=json.Marshal(peers);if err!=nil{t.Fatal(err)}
    input:=filepath.Join(gatewayDir,"peers.json")
    if err:=os.WriteFile(input,payload,0600);err!=nil{t.Fatal(err)}
    output:=filepath.Join(gatewayDir,"gateway.conf")
    if err:=writeGatewayConfiguration(gatewayDir,input,output,51820);err!=nil{t.Fatal(err)}
    info,err:=os.Stat(output);if err!=nil{t.Fatal(err)}
    if info.Mode().Perm()!=0600{t.Fatal("gateway config file is not private")}
    content,err:=os.ReadFile(output);if err!=nil{t.Fatal(err)}
    if !strings.Contains(string(content),"AllowedIPs = 10.77.0.2/32"){t.Fatal("missing peer-specific allowed address")}
    if strings.Contains(string(content),"0.0.0.0/0"){t.Fatal("unexpected full-tunnel route")}
    if err:=writeGatewayConfiguration(gatewayDir,input,output,51820);err==nil{t.Fatal("overwrote gateway configuration")}
}
