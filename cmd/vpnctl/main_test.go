package main

import (
 "os"
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
