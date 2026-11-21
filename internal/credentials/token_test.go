package credentials

import (
    "os"
    "path/filepath"
    "testing"
)

func TestPrivateTokenLifecycle(t *testing.T){
    path:=filepath.Join(t.TempDir(),"private","admin-token")
    if err:=Create(path);err!=nil{t.Fatal(err)}
    fi,err:=os.Stat(path);if err!=nil{t.Fatal(err)}
    if fi.Mode().Perm()!=0600{t.Fatalf("unsafe mode %v",fi.Mode())}
    tok,err:=Read(path);if err!=nil{t.Fatal(err)}
    if len(tok)!=64{t.Fatalf("length %d",len(tok))}
    if err:=Create(path);err==nil{t.Fatal("token overwritten")}
    if err:=os.Chmod(path,0644);err!=nil{t.Fatal(err)}
    if _,err:=Read(path);err==nil{t.Fatal("read insecure token file")}
}

func TestUnsafeParentRejected(t *testing.T){
    parent:=filepath.Join(t.TempDir(),"notprivate")
    if err:=os.Mkdir(parent,0700);err!=nil{t.Fatal(err)}
    if err:=os.Chmod(parent,0777);err!=nil{t.Fatal(err)}
    if err:=Create(filepath.Join(parent,"token"));err==nil{t.Fatal("accepted unsafe parent")}
}
