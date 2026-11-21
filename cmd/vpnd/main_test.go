package main

import "testing"

func TestListenSecurity(t *testing.T){
    for _,address:=range []string{"0.0.0.0:8788","192.168.1.10:8788","[::]:8788"}{
        if err:=validateListener(address,"","");err==nil{t.Fatalf("unsafe plaintext listener allowed: %s",address)}
        if err:=validateListener(address,"cert.pem","key.pem");err!=nil{t.Fatalf("TLS listener refused: %v",err)}
    }
    for _,address:=range []string{"127.0.0.1:8788","localhost:8788","[::1]:8788"}{
        if err:=validateListener(address,"","");err!=nil{t.Fatalf("loopback listener refused: %v",err)}
    }
    if err:=validateListener("0.0.0.0:8788","cert.pem","");err==nil{t.Fatal("accepted certificate without key")}
    if err:=validateListener("unsafe.test:8788","cert.pem","key.pem");err==nil{t.Fatal("accepted unverified hostname")}
}
