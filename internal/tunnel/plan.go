// Package tunnel defines a separate, least-privilege Linux WireGuard data-plane
// operation. No plan command executes shell or changes a host network.
package tunnel

import (
    "crypto/ecdh"
    "encoding/base64"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "os"
    "path/filepath"
    "strings"

    "github.com/GoreeCloud/VPN/internal/wireguard"
)

const Interface = "gcvpn0"
const Route = "10.77.0.0/24"

type Settings struct {
    PrivateKeyFile string
    GatewayPublicKey string
    ClientAddress string
    Endpoint string
}

type Step struct {
    Program string
    Args []string
}

func (s Step) String() string { return s.Program + " " + strings.Join(s.Args, " ") }

func checkedPrivate(path string)(string,error){
    if path=="" || !filepath.IsAbs(path) { return "",errors.New("private key must be at an absolute path") }
    fi,err:=os.Lstat(path)
    if err!=nil{return "",err}
    if !fi.Mode().IsRegular() || fi.Mode().Perm()!=0600 || fi.Size()>256 {
        return "",errors.New("WireGuard private-key file must be a mode-0600 regular file")
    }
    b,err:=os.ReadFile(path);if err!=nil{return "",err}
    v:=strings.TrimSuffix(string(b),"\n")
    if strings.TrimSpace(v)!=v || len(v)!=44{return "",errors.New("invalid key-file contents")}
    raw,err:=base64.StdEncoding.DecodeString(v)
    if err!=nil || len(raw)!=32{return "",errors.New("invalid base64 X25519 private key")}
    if _,err=ecdh.X25519().NewPrivateKey(raw);err!=nil{return "",err}
    return v,nil
}

func validateEndpoint(endpoint string)error {
    host,port,err:=net.SplitHostPort(endpoint)
    if err!=nil || host=="" || port==""{return errors.New("invalid gateway endpoint")}
    if endpoint=="0.0.0.0:0"{return errors.New("wildcard endpoint not allowed")}
    return nil
}

func Plan(settings Settings)([]Step,error){
    private,err:=checkedPrivate(settings.PrivateKeyFile)
    if err!=nil{return nil,err}
    if err=validateEndpoint(settings.Endpoint);err!=nil{return nil,err}
    rendered,err:=wireguard.RenderClientConfig(wireguard.ClientOptions{
        PrivateKey:private,Address:settings.ClientAddress,
        GatewayPublicKey:settings.GatewayPublicKey,Endpoint:settings.Endpoint,
    })
    // Do not log, return or persist the rendered config containing private key.
    if err!=nil{return nil,err}
    _=rendered
    addr,err:=netip.ParsePrefix(settings.ClientAddress)
    if err!=nil || addr.Bits()!=32{return nil,errors.New("client /32 required")}
    return []Step{
        {Program:"ip",Args:[]string{"link","add","dev",Interface,"type","wireguard"}},
        {Program:"wg",Args:[]string{"set",Interface,"private-key",settings.PrivateKeyFile,
            "peer",settings.GatewayPublicKey,"endpoint",settings.Endpoint,
            "allowed-ips",Route,"persistent-keepalive","25"}},
        {Program:"ip",Args:[]string{"-4","address","add",settings.ClientAddress,"dev",Interface}},
        {Program:"ip",Args:[]string{"link","set","dev",Interface,"up"}},
        {Program:"ip",Args:[]string{"-4","route","add",Route,"dev",Interface}},
    },nil
}

type Runner func(program string,args ...string)error

// Apply is injectable for isolated tests. The root-only CLI wrapper must
// independently ensure the target interface and the route do not already exist.
func Apply(steps []Step, run Runner)error{
    if len(steps)!=5{return errors.New("invalid data-plane plan length")}
    created:=false
    for i,cmd:=range steps{
        if i==0 && (cmd.Program!="ip" || strings.Join(cmd.Args," ")!="link add dev gcvpn0 type wireguard"){
            return errors.New("invalid first step")
        }
        if err:=run(cmd.Program,cmd.Args...);err!=nil{
            if created {
                // Deleting the newly created interface normally removes its device route.
                rollback:=run("ip","link","delete","dev",Interface)
                if rollback!=nil {
                    return fmt.Errorf("operation step %d failed AND rollback failed; manual network inspection required: %w",i+1,err)
                }
            }
            return fmt.Errorf("operation step %d failed, newly created interface rolled back when possible: %w",i+1,err)
        }
        if i==0{created=true}
    }
    return nil
}

func Stop(run Runner)error {
    return run("ip","link","delete","dev",Interface)
}
