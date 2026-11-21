// vpnd is a first-party GoreeCloud VPN control-plane preview.
// It does not install a tunnel, modify iptables, or interact with NetBird.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/GoreeCloud/VPN/internal/api"
	"github.com/GoreeCloud/VPN/internal/control"
	"github.com/GoreeCloud/VPN/internal/credentials"
)

func defaultPaths() (string, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "state", ".config/goreecloud/vpn/admin-token"
	}
	return filepath.Join(home, ".local/share/goreecloud/vpn"), filepath.Join(home, ".config/goreecloud/vpn/admin-token")
}

func validateListener(address, cert, key string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if (cert == "") != (key == "") {
		return errors.New("provide both --tls-cert and --tls-key")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("listen hostname must be localhost or a literal IP")
	}
	if !ip.IsLoopback() && cert == "" {
		return errors.New("non-loopback listener requires TLS certificate and key")
	}
	return nil
}

func main() {
	stateDefault, tokenDefault := defaultPaths()
	addr := flag.String("listen", "127.0.0.1:8788", "local bind, or explicit TLS-protected remote IP")
	stateDir := flag.String("state-dir", stateDefault, "private local control-plane state")
	tokenFile := flag.String("token-file", tokenDefault, "private mode-0600 administrator token file")
	cert := flag.String("tls-cert", "", "TLS certificate (required for non-loopback)")
	key := flag.String("tls-key", "", "TLS private key (required for non-loopback)")
	webRoot := flag.String("web-root", "", "optional local static web app directory; same origin as API")
	flag.Parse()
	if err := validateListener(*addr, *cert, *key); err != nil {
		log.Fatal(err)
	}
	token, err := credentials.Read(*tokenFile)
	if err != nil {
		log.Fatalf("cannot load private token: %v", err)
	}
	store, err := control.Open(*stateDir)
	if err != nil {
		log.Fatalf("cannot open control-plane state: %v", err)
	}
	defer store.Close()
	handler, err := api.NewHandler(store, token, *webRoot)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr: *addr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
	}
	fmt.Fprintf(os.Stderr, "GoreeCloud VPN CONTROL-PLANE PREVIEW on %s; no WireGuard tunnel installed\n", *addr)
	if *cert != "" {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}
