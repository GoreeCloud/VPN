//go:build linux

// vpnagent is a separately privileged Linux WireGuard interface reconciler.
// Nothing executes without --confirm-apply/--acknowledge-network-impact and root.
package main

import (
    "context"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"

    "github.com/GoreeCloud/VPN/internal/tunnel"
)

const agentState = "/var/lib/goreecloud-vpn-agent"
const markerName = "active.json"

type marker struct {
    Interface string `json:"interface"`
    Route string `json:"route"`
    Address string `json:"address"`
}

// Resolve expected Linux utilities without executing tools from an arbitrary PATH.
func safeBinary(name string)(string,error){
    if name!="ip" && name!="wg"{return "",errors.New("unsupported tool")}
    for _,dir:=range []string{"/usr/bin","/usr/sbin","/bin","/sbin"}{
        p:=filepath.Join(dir,name)
        info,err:=os.Stat(p)
        if err!=nil{continue}
        sys:=info.Sys()
        _=sys
        if info.Mode().IsRegular() && info.Mode().Perm()&0022==0 {
            return p,nil
        }
    }
    return "",fmt.Errorf("reviewed Linux command %s not found",name)
}

func execute(program string,args ...string)error{
    bin,err:=safeBinary(program)
    if err!=nil{return err}
    ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
    defer cancel()
    cmd:=exec.CommandContext(ctx,bin,args...)
    // No shell, secret never in argv. Output not forwarded to logs.
    if err=cmd.Run();err!=nil{return fmt.Errorf("%s operation failed: %w",program,err)}
    return nil
}

func output(program string,args ...string)(string,error){
    bin,err:=safeBinary(program)
    if err!=nil{return "",err}
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    data,err:=exec.CommandContext(ctx,bin,args...).Output()
    if err!=nil{return "",err}
    if len(data)>4096{return "",errors.New("network query output too large")}
    return string(data),nil
}

func ownerMarker()string{return filepath.Join(agentState,markerName)}

func preflight()error{
    if os.Geteuid()!=0{return errors.New("network mutations require root / narrow CAP_NET_ADMIN context")}
    if _,err:=os.Lstat(ownerMarker());err==nil{return errors.New("VPN agent already has active ownership marker")}
    if text,err:=output("ip","link","show","dev",tunnel.Interface);err==nil || strings.TrimSpace(text)!="" {
        return errors.New("target interface already exists, refusing to alter it")
    }
    existing,err:=output("ip","-4","route","show","exact",tunnel.Route)
    if err!=nil{return fmt.Errorf("cannot inspect existing routes: %w",err)}
    if strings.TrimSpace(existing)!=""{return errors.New("VPN subnet route already exists: refusing network change")}
    return nil
}

func saveMarker(addr string)error{
    if err:=os.MkdirAll(agentState,0700);err!=nil{return err}
    info,err:=os.Lstat(agentState)
    if err!=nil{return err}
    if !info.IsDir() || info.Mode().Perm()&0077!=0 || info.Mode()&os.ModeSymlink!=0{
        return errors.New("unsafe agent state directory")
    }
    content,err:=json.Marshal(marker{Interface:tunnel.Interface,Route:tunnel.Route,Address:addr})
    if err!=nil{return err}
    f,err:=os.OpenFile(ownerMarker(),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
    if err!=nil{return err}
    if _,err=f.Write(content);err!=nil{f.Close();os.Remove(ownerMarker());return err}
    if err=f.Sync();err!=nil{f.Close();os.Remove(ownerMarker());return err}
    return f.Close()
}

func readMarker()(marker,error){
    var m marker
    info,err:=os.Lstat(ownerMarker())
    if err!=nil{return m,err}
    if !info.Mode().IsRegular() || info.Mode().Perm()!=0600 || info.Size()>1024 {
        return m,errors.New("unsafe agent state marker")
    }
    data,err:=os.ReadFile(ownerMarker());if err!=nil{return m,err}
    if err=json.Unmarshal(data,&m);err!=nil{return m,err}
    if m.Interface!=tunnel.Interface || m.Route!=tunnel.Route{
        return m,errors.New("foreign interface ownership marker")
    }
    return m,nil
}

func main(){
    mode:=flag.String("action","plan","plan, apply, or stop")
    keyPath:=flag.String("private-key-file","","absolute path to owner-only 0600 WireGuard key")
    gatewayPath:=flag.String("gateway-public-key-file","","reviewed peer public key file")
    addr:=flag.String("address","","assigned 10.77.0.x/32")
    endpoint:=flag.String("endpoint","","reviewed gateway host:port")
    confirm:=flag.Bool("confirm-apply",false,"explicitly authorize interface creation")
    ack:=flag.Bool("acknowledge-network-impact",false,"acknowledge routing and interface changes")
    confirmStop:=flag.Bool("confirm-stop",false,"authorize deletion of agent-owned interface")
    flag.Parse()
    if *mode=="stop" {
        if !*confirmStop || !*ack{fatal(errors.New("stop requires --confirm-stop and --acknowledge-network-impact"))}
        if os.Geteuid()!=0{fatal(errors.New("root required to stop interface"))}
        if _,err:=readMarker();err!=nil{fatal(fmt.Errorf("no owned interface marker: %w",err))}
        detail,err:=output("ip","-d","link","show","dev",tunnel.Interface)
        if err!=nil || !strings.Contains(detail,"wireguard"){
            fatal(errors.New("interface is not confirmed as an agent-managed WireGuard interface"))
        }
        if err:=tunnel.Stop(execute);err!=nil{fatal(err)}
        if err:=os.Remove(ownerMarker());err!=nil{fatal(err)}
        fmt.Println("Agent-owned interface removed. No other network interfaces were modified.")
        return
    }
    if *mode!="plan" && *mode!="apply"{fatal(errors.New("invalid action"))}
    gatewayInfo,err:=os.Lstat(*gatewayPath);if err!=nil{fatal(err)}
    if !gatewayInfo.Mode().IsRegular() || gatewayInfo.Size()>256{fatal(errors.New("gateway public key file must be a small regular file"))}
    pub,err:=os.ReadFile(*gatewayPath);if err!=nil{fatal(err)}
    settings:=tunnel.Settings{
        PrivateKeyFile:*keyPath,GatewayPublicKey:strings.TrimSpace(string(pub)),
        ClientAddress:*addr,Endpoint:*endpoint,
    }
    steps,err:=tunnel.Plan(settings);if err!=nil{fatal(err)}
    if *mode=="plan" {
        fmt.Println("DRY RUN ONLY — no network commands executed")
        for _,step:=range steps{fmt.Println(step.String())}
        fmt.Println("No tunnel is activated; a configured gateway is also required.")
        return
    }
    if !*confirm || !*ack{fatal(errors.New("apply requires both --confirm-apply and --acknowledge-network-impact"))}
    if err:=preflight();err!=nil{fatal(err)}
    if err:=tunnel.Apply(steps,execute);err!=nil{fatal(err)}
    if err:=saveMarker(settings.ClientAddress);err!=nil {
        rollback:=tunnel.Stop(execute)
        if rollback!=nil{fatal(fmt.Errorf("marker write failed AND rollback failed: %w",err))}
        fatal(fmt.Errorf("marker write failed, interface removed: %w",err))
    }
    fmt.Println("Agent-owned WireGuard interface configured. Verify a real handshake, DNS and routes independently.")
}

func fatal(err error){
    fmt.Fprintln(os.Stderr,"vpnagent:",err)
    os.Exit(2)
}
