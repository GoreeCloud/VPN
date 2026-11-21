// Package credentials handles owner-private local administrator tokens.
package credentials

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "os"
    "path/filepath"
    "strings"
)

func Read(path string)(string,error){
    fi,err:=os.Lstat(path)
    if err!=nil{return "",err}
    if !fi.Mode().IsRegular() || fi.Mode().Perm()!=0600 || fi.Size()>4096 {
        return "",errors.New("administrator token file must be a regular mode-0600 file <= 4096 bytes")
    }
    b,err:=os.ReadFile(path);if err!=nil{return "",err}
    token:=strings.TrimSpace(string(b))
    if len(token)<32 || strings.ContainsAny(token,"\r\n\t "){return "",errors.New("invalid administrator token file")}
    return token,nil
}

func Create(path string)error{
    if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err}
    dir,err:=os.Lstat(filepath.Dir(path));if err!=nil{return err}
    if !dir.IsDir() || dir.Mode()&os.ModeSymlink!=0 || dir.Mode().Perm()&0077!=0 {
        return errors.New("token directory must be private (0700), not symlink")
    }
    buf:=make([]byte,32)
    if _,err:=rand.Read(buf);err!=nil{return err}
    file,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
    if err!=nil{return err}
    token:=hex.EncodeToString(buf)+"\n"
    if _,err:=file.WriteString(token);err!=nil{file.Close();os.Remove(path);return err}
    if err:=file.Sync();err!=nil{file.Close();os.Remove(path);return err}
    return file.Close()
}
