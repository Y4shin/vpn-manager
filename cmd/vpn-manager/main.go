package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"

	"github.com/patric/vpn-manager/internal/config"
	"github.com/patric/vpn-manager/internal/ipam"
	"github.com/patric/vpn-manager/internal/oidc"
	"github.com/patric/vpn-manager/internal/store"
	"github.com/patric/vpn-manager/internal/web"
	"github.com/patric/vpn-manager/internal/wg"
)

func main() {
	cfgPath := flag.String("config", "/etc/vpn-manager/config.yaml", "path to config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	st, err := store.Open(cfg.DataDir + "/vpn-manager.sqlite")
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	sm := scs.New()
	sm.Store = sqlite3store.New(st.DB)
	sm.Lifetime = 12 * time.Hour
	sm.Cookie.Secure = strings.HasPrefix(cfg.PublicURL, "https://")
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode

	groupCIDRs := make(map[string]string, len(cfg.Groups))
	for n, g := range cfg.Groups {
		groupCIDRs[n] = g.CIDR
	}
	alloc, err := ipam.New(groupCIDRs)
	if err != nil {
		log.Fatalf("ipam: %v", err)
	}

	wgCtrl, err := wg.New(cfg)
	if err != nil {
		log.Fatalf("wgctrl: %v", err)
	}
	defer wgCtrl.Close()
	if err := wgCtrl.Bootstrap(); err != nil {
		log.Fatalf("wg bootstrap: %v", err)
	}
	if err := applyAllPeers(context.Background(), st, wgCtrl); err != nil {
		log.Fatalf("initial peer sync: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	authHandler, err := oidc.New(ctx, cfg, st, sm)
	if err != nil {
		log.Fatalf("oidc: %v", err)
	}

	server, err := web.New(cfg, st, authHandler, sm, wgCtrl, alloc)
	if err != nil {
		log.Fatalf("web: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go reconcile(ctx, st, wgCtrl, 30*time.Second)

	go func() {
		log.Printf("vpn-manager listening on %s", cfg.ListenAddr)
		log.Printf("wg-users pubkey: %s", wgCtrl.UsersPublicKey())
		log.Printf("wg-home  pubkey: %s", wgCtrl.HomePublicKey())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("shutting down")
	shutdownCtx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func applyAllPeers(ctx context.Context, st *store.Store, wc *wg.Controller) error {
	devs, err := st.ListAllDevices(ctx)
	if err != nil {
		return err
	}
	peers := make([]wg.UserPeer, 0, len(devs))
	for _, d := range devs {
		peers = append(peers, wg.UserPeer{PublicKey: d.PublicKey, IP: d.IP})
	}
	return wc.Apply(peers)
}

// reconcile periodically (a) re-applies the peer set from the DB in case
// something drifted, and (b) pulls latest handshake timestamps into the DB.
func reconcile(ctx context.Context, st *store.Store, wc *wg.Controller, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := applyAllPeers(ctx, st, wc); err != nil {
			log.Printf("reconcile peers: %v", err)
			continue
		}
		hs, err := wc.Handshakes()
		if err != nil {
			log.Printf("reconcile handshakes: %v", err)
			continue
		}
		for pubkey, ts := range hs {
			if ts.IsZero() {
				continue
			}
			if err := st.UpdateHandshake(ctx, pubkey, ts); err != nil {
				log.Printf("update handshake for %s: %v", pubkey, err)
			}
		}
	}
}
