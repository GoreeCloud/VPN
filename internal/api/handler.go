// Package api exposes a minimal authenticated GoreeCloud VPN control-plane API.
// A peer registry is not a working WireGuard tunnel; data-plane setup is separate.
package api

import (
    "crypto/sha256"
    "crypto/subtle"
    "encoding/json"
    "errors"
    "io"
    "net/http"
    "regexp"
    "strings"

    "github.com/GoreeCloud/VPN/internal/control"
)

const maxBody = 8 << 10
var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Handler struct {
    store *control.Store
    secret [32]byte
    webRoot string
}

type peerInput struct {
    Name string `json:"name"`
    PublicKey string `json:"public_key"`
}

func NewHandler(store *control.Store, token, webRoot string) (http.Handler,error) {
    if store == nil || len(token) < 32 || len(token)>4096 || strings.TrimSpace(token)!=token || strings.ContainsAny(token,"\r\n\t") {
        return nil,errors.New("server requires a random administrator token of at least 32 characters")
    }
    h:=&Handler{store:store,secret:sha256.Sum256([]byte(token)),webRoot:webRoot}
    return h,nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter,r *http.Request) {
    w.Header().Set("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    w.Header().Set("X-Content-Type-Options","nosniff")
    w.Header().Set("X-Frame-Options","DENY")
    w.Header().Set("Referrer-Policy","no-referrer")
    w.Header().Set("Cache-Control","no-store")
    if r.URL.Path=="/healthz" {
        if r.Method!="GET" { w.Header().Set("Allow","GET");h.failure(w,http.StatusMethodNotAllowed,"method not allowed");return }
        h.respond(w,http.StatusOK,map[string]string{"status":"ok"})
        return
    }
    if r.URL.Path=="/" && h.webRoot!="" && r.Method=="GET" {
        http.ServeFile(w,r,h.webRoot+"/index.html")
        return
    }
    if (r.URL.Path=="/app.js" || r.URL.Path=="/style.css") && h.webRoot!="" && r.Method=="GET" {
        http.ServeFile(w,r,h.webRoot+r.URL.Path)
        return
    }
    if !h.authorized(r) {
        w.Header().Set("WWW-Authenticate",`Bearer realm="GoreeCloud VPN"`)
        h.failure(w,http.StatusUnauthorized,"authentication required")
        return
    }
    if r.URL.Path=="/v1/info" {
        if r.Method!="GET"{w.Header().Set("Allow","GET");h.failure(w,405,"method not allowed");return}
        h.respond(w,200,map[string]interface{}{"product":"GoreeCloud VPN","api_version":"v1","state":"control-plane preview","tunnel_operational":false})
        return
    }
    if r.URL.Path=="/v1/peers" {
        switch r.Method {
        case "GET": h.respond(w,200,map[string]interface{}{"peers":h.store.List()})
        case "POST": h.createPeer(w,r)
        default: w.Header().Set("Allow","GET, POST");h.failure(w,405,"method not allowed")
        }
        return
    }
    if strings.HasPrefix(r.URL.Path,"/v1/peers/") && strings.HasSuffix(r.URL.Path,"/revoke") {
        id:=strings.TrimSuffix(strings.TrimPrefix(r.URL.Path,"/v1/peers/"),"/revoke")
        if !idPattern.MatchString(id){h.failure(w,404,"not found");return}
        if r.Method!="POST"{w.Header().Set("Allow","POST");h.failure(w,405,"method not allowed");return}
        peer,err:=h.store.Revoke(id)
        if errors.Is(err,control.ErrNotFound){h.failure(w,404,"peer not found");return}
        if errors.Is(err,control.ErrRevoked){h.failure(w,409,"peer already revoked");return}
        if err!=nil{h.failure(w,500,"persistent state update failed");return}
        h.respond(w,200,peer)
        return
    }
    h.failure(w,404,"not found")
}

func (h *Handler) authorized(r *http.Request) bool {
    // Reject duplicated Authorization headers instead of relying on implicit merging.
    if len(r.Header.Values("Authorization"))!=1{return false}
    raw:=r.Header.Get("Authorization")
    if !strings.HasPrefix(raw,"Bearer "){return false}
    token:=strings.TrimPrefix(raw,"Bearer ")
    if len(token)<32 || len(token)>4096{return false}
    digest:=sha256.Sum256([]byte(token))
    return subtle.ConstantTimeCompare(h.secret[:],digest[:])==1
}

func (h *Handler) createPeer(w http.ResponseWriter,r *http.Request) {
    if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")),"application/json") {
        h.failure(w,415,"application/json required")
        return
    }
    r.Body=http.MaxBytesReader(w,r.Body,maxBody)
    d:=json.NewDecoder(r.Body)
    d.DisallowUnknownFields()
    var input peerInput
    if err:=d.Decode(&input);err!=nil{h.failure(w,400,"invalid peer JSON");return}
    var extra interface{}
    if err:=d.Decode(&extra);!errors.Is(err,io.EOF){h.failure(w,400,"unexpected JSON content");return}
    peer,err:=h.store.Add(input.Name,input.PublicKey)
    if errors.Is(err,control.ErrInvalid){h.failure(w,422,"invalid name or public key");return}
    if errors.Is(err,control.ErrDuplicate){h.failure(w,409,"public key already registered");return}
    if errors.Is(err,control.ErrFull){h.failure(w,507,"address pool exhausted");return}
    if err!=nil{h.failure(w,500,"persistent state update failed");return}
    h.respond(w,http.StatusCreated,peer)
}

func (h *Handler) respond(w http.ResponseWriter,status int,body interface{}) {
    w.Header().Set("Content-Type","application/json; charset=utf-8")
    w.WriteHeader(status)
    _=json.NewEncoder(w).Encode(body)
}

func (h *Handler) failure(w http.ResponseWriter,status int,msg string) {
    h.respond(w,status,map[string]string{"error":msg})
}
