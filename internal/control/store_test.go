package control

import (
    "crypto/ecdh"
    "crypto/rand"
    "encoding/base64"
    "os"
    "path/filepath"
    "sync"
    "testing"
)

func newKey(t *testing.T) string {
    t.Helper()
    k,err:=ecdh.X25519().GenerateKey(rand.Reader)
    if err!=nil{t.Fatal(err)}
    return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func TestPersistenceAndRevocation(t *testing.T) {
    dir:=filepath.Join(t.TempDir(),"private")
    s,err:=Open(dir);if err!=nil{t.Fatal(err)}
    p,err:=s.Add("trusted-laptop",newKey(t));if err!=nil{t.Fatal(err)}
    if p.Address!="10.77.0.2/32"{t.Fatalf("wrong address %s",p.Address)}
    if _,err:=s.Add("duplicate",p.PublicKey);err!=ErrDuplicate{t.Fatalf("duplicate allowed: %v",err)}
    if fi,err:=os.Stat(filepath.Join(dir,"state.json"));err!=nil || fi.Mode().Perm()!=0600 {t.Fatalf("unsafe state file: %v %v",fi,err)}
    other,err:=Open(dir);if err!=nil{t.Fatal(err)}
    if got:=other.List();len(got)!=1 || got[0].ID!=p.ID{t.Fatalf("state lost: %+v",got)}
    revoked,err:=other.Revoke(p.ID);if err!=nil{t.Fatal(err)}
    if revoked.RevokedAt==nil{t.Fatal("missing revocation timestamp")}
    if _,err:=other.Revoke(p.ID);err!=ErrRevoked{t.Fatalf("revocation not idempotently denied %v",err)}
    next,err:=other.Add("new-laptop",newKey(t));if err!=nil{t.Fatal(err)}
    if next.Address!="10.77.0.3/32"{t.Fatal("revoked address was reused")}
}

func TestInvalidInputsAndDirectoryPermissions(t *testing.T){
    s,err:=Open(filepath.Join(t.TempDir(),"private"));if err!=nil{t.Fatal(err)}
    for _,name:=range []string{"","../sneaky","bad/name"," whitespaced",string(make([]byte,80))} {
        if _,err:=s.Add(name,newKey(t));err!=ErrInvalid{t.Fatalf("accepted invalid name %q: %v",name,err)}
    }
    for _,key:=range []string{"", "secret",base64.StdEncoding.EncodeToString(make([]byte,32))}{
        if _,err:=s.Add("normal",key);err!=ErrInvalid{t.Fatalf("accepted key %q: %v",key,err)}
    }
    insecure:=filepath.Join(t.TempDir(),"insecure")
    if err:=os.Mkdir(insecure,0777);err!=nil{t.Fatal(err)}
    if err:=os.Chmod(insecure,0777);err!=nil{t.Fatal(err)}
    if _,err:=Open(insecure);err==nil{t.Fatal("accepted world-accessible state directory")}
}

func TestConcurrentUniqueAllocation(t *testing.T){
    s,err:=Open(filepath.Join(t.TempDir(),"private"));if err!=nil{t.Fatal(err)}
    keys:=make([]string,20)
    for i:=range keys{keys[i]=newKey(t)}
    var wg sync.WaitGroup
    errCh:=make(chan error,len(keys))
    for i:=range keys{
        wg.Add(1)
        go func(n int){defer wg.Done();_,err:=s.Add("client",keys[n]);errCh<-err}(i)
    }
    wg.Wait();close(errCh)
    for err:=range errCh{if err!=nil{t.Fatal(err)}}
    addresses:=map[string]bool{}
    for _,p:=range s.List(){if addresses[p.Address]{t.Fatal("address collision")};addresses[p.Address]=true}
    if len(addresses)!=len(keys){t.Fatalf("lost writes: %d",len(addresses))}
}
