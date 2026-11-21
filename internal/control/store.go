// Package control provides the first-party GoreeCloud VPN peer registry.
// It does not configure a WireGuard interface or claim an active encrypted tunnel.
package control

import (
    "crypto/ecdh"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "regexp"
    "sort"
    "sync"
    "time"
)

var (
    ErrDuplicate = errors.New("peer public key already registered")
    ErrNotFound = errors.New("peer not found")
    ErrRevoked = errors.New("peer already revoked")
    ErrFull = errors.New("peer address pool exhausted")
    ErrInvalid = errors.New("invalid peer name or WireGuard public key")
)

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// Peer is public control-plane metadata, NEVER a WireGuard private key.
type Peer struct {
    ID string `json:"id"`
    Name string `json:"name"`
    PublicKey string `json:"public_key"`
    Address string `json:"address"`
    CreatedAt time.Time `json:"created_at"`
    RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type persisted struct {
    Version int `json:"version"`
    Peers []Peer `json:"peers"`
}

type Store struct {
    mu sync.Mutex
    dir string
    state persisted
}

func Open(dir string) (*Store, error) {
    if dir == "" { return nil, errors.New("missing state directory") }
    if err := os.MkdirAll(dir, 0700); err != nil { return nil, fmt.Errorf("make private state directory: %w", err) }
    info, err := os.Lstat(dir)
    if err != nil { return nil, err }
    if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
        return nil, errors.New("state directory must be a non-symlink private directory (0700)")
    }
    s := &Store{dir: dir, state: persisted{Version: 1, Peers: []Peer{}}}
    file := filepath.Join(dir, "state.json")
    fi, err := os.Lstat(file)
    if errors.Is(err, os.ErrNotExist) { return s, nil }
    if err != nil { return nil, err }
    if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 || fi.Size() > 2<<20 {
        return nil, errors.New("unsafe or oversized state file")
    }
    b, err := os.ReadFile(file)
    if err != nil { return nil, err }
    if err := json.Unmarshal(b, &s.state); err != nil { return nil, fmt.Errorf("invalid stored state: %w", err) }
    if s.state.Version != 1 { return nil, errors.New("unsupported state schema version") }
    seenID, seenAddress, seenKey := map[string]bool{}, map[string]bool{}, map[string]bool{}
    for _, p := range s.state.Peers {
        if p.ID == "" || seenID[p.ID] || seenAddress[p.Address] || seenKey[p.PublicKey] || !validName.MatchString(p.Name) || !ValidPublicKey(p.PublicKey) {
            return nil, errors.New("inconsistent stored peer registry")
        }
        seenID[p.ID], seenAddress[p.Address], seenKey[p.PublicKey] = true, true, true
    }
    if s.state.Peers == nil { s.state.Peers = []Peer{} }
    return s, nil
}

func ValidPublicKey(v string) bool {
    raw, err := base64.StdEncoding.DecodeString(v)
    if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != v { return false }
    var nonzero byte
    for _, b := range raw { nonzero |= b }
    if nonzero == 0 { return false }
    _, err = ecdh.X25519().NewPublicKey(raw)
    return err == nil
}

func (s *Store) List() []Peer {
    s.mu.Lock()
    defer s.mu.Unlock()
    out := append([]Peer(nil), s.state.Peers...)
    sort.Slice(out, func(i,j int)bool { return out[i].CreatedAt.Before(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID) })
    return out
}

func (s *Store) Add(name, publicKey string) (Peer, error) {
    if !validName.MatchString(name) || !ValidPublicKey(publicKey) { return Peer{}, ErrInvalid }
    s.mu.Lock()
    defer s.mu.Unlock()
    used := make(map[string]bool)
    for _, p := range s.state.Peers {
        if p.PublicKey == publicKey { return Peer{}, ErrDuplicate }
        used[p.Address] = true
    }
    address := ""
    for n:=2; n<=254; n++ {
        candidate := fmt.Sprintf("10.77.0.%d/32", n)
        if !used[candidate] { address=candidate; break }
    }
    if address=="" { return Peer{}, ErrFull }
    buf:=make([]byte,16)
    if _,err:=io.ReadFull(rand.Reader,buf);err!=nil{return Peer{},err}
    p:=Peer{ID:hex.EncodeToString(buf),Name:name,PublicKey:publicKey,Address:address,CreatedAt:time.Now().UTC()}
    next:=persisted{Version:1,Peers:append(append([]Peer(nil),s.state.Peers...),p)}
    if err:=s.save(next);err!=nil{return Peer{},err}
    s.state=next
    return p,nil
}

func (s *Store) Revoke(id string) (Peer,error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    peers:=append([]Peer(nil),s.state.Peers...)
    for i := range peers {
        if peers[i].ID!=id { continue }
        if peers[i].RevokedAt!=nil{return Peer{},ErrRevoked}
        now:=time.Now().UTC()
        peers[i].RevokedAt=&now
        next:=persisted{Version:1,Peers:peers}
        if err:=s.save(next);err!=nil{return Peer{},err}
        s.state=next
        return peers[i],nil
    }
    return Peer{},ErrNotFound
}

func (s *Store) save(next persisted) error {
    data,err:=json.MarshalIndent(next,"","  ")
    if err!=nil{return err}
    if len(data)>2<<20{return errors.New("state file exceeded safety limit")}
    f,err:=os.CreateTemp(s.dir,".state-")
    if err!=nil{return err}
    tmp:=f.Name()
    defer os.Remove(tmp)
    if err:=f.Chmod(0600);err!=nil{f.Close();return err}
    if _,err=f.Write(data);err!=nil{f.Close();return err}
    if err=f.Sync();err!=nil{f.Close();return err}
    if err=f.Close();err!=nil{return err}
    return os.Rename(tmp,filepath.Join(s.dir,"state.json"))
}
