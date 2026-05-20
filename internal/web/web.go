package web

import (
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/patric/vpn-manager/internal/config"
	"github.com/patric/vpn-manager/internal/ipam"
	"github.com/patric/vpn-manager/internal/oidc"
	"github.com/patric/vpn-manager/internal/render"
	"github.com/patric/vpn-manager/internal/store"
	"github.com/patric/vpn-manager/internal/wg"
)

//go:embed templates/*.html
var tplFS embed.FS

//go:embed static/*
var staticFS embed.FS

const flashKey = "ui.flash"

var pageTemplates = []string{"login.html", "dashboard.html", "device_created.html"}

type Server struct {
	cfg       *config.Config
	store     *store.Store
	auth      *oidc.Handler
	session   *scs.SessionManager
	wg        wg.WGControl
	allocator *ipam.Allocator
	pages     map[string]*template.Template
}

func New(
	cfg *config.Config, st *store.Store, auth *oidc.Handler,
	sm *scs.SessionManager, wc wg.WGControl, alloc *ipam.Allocator,
) (*Server, error) {
	pages := make(map[string]*template.Template, len(pageTemplates))
	for _, p := range pageTemplates {
		t, err := template.ParseFS(tplFS, "templates/base.html", "templates/"+p)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		pages[p] = t
	}
	return &Server{
		cfg: cfg, store: st, auth: auth, session: sm,
		wg: wc, allocator: alloc, pages: pages,
	}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /auth/login", s.auth.Login)
	mux.HandleFunc("GET /auth/callback", s.auth.Callback)
	mux.HandleFunc("POST /auth/logout", s.auth.Logout)

	authed := http.NewServeMux()
	authed.HandleFunc("GET /", s.dashboard)
	authed.HandleFunc("POST /devices", s.createDevice)
	authed.HandleFunc("POST /devices/{id}/delete", s.deleteDevice)

	mux.Handle("/", s.routeRoot(authed))

	return s.session.LoadAndSave(mux)
}

// routeRoot serves the public landing page for unauthenticated users
// and otherwise delegates to the authed mux.
func (s *Server) routeRoot(authed http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.auth.CurrentUser(r); !ok {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			s.render(w, r, "login.html", nil)
			return
		}
		authed.ServeHTTP(w, r)
	})
}

type baseData struct {
	User  *oidc.SessionUser
	Flash string
}

type dashboardData struct {
	baseData
	Devices   []store.Device
	Group     string
	GroupCIDR string
	NoGroup   bool
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	user, _ := s.auth.CurrentUser(r)

	devices, err := s.store.ListDevicesByUser(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	group := s.allocator.GroupForUserGroups(user.Groups, s.cfg.Default)
	data := dashboardData{
		baseData: baseData{User: user, Flash: s.popFlash(r)},
		Devices:  devices,
	}
	if group == "" {
		data.NoGroup = true
	} else {
		data.Group = group
		data.GroupCIDR = s.cfg.Groups[group].CIDR
	}
	s.render(w, r, "dashboard.html", data)
}

type createdData struct {
	baseData
	Device  *store.Device
	Conf    string
	ConfB64 string
	QR      string
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	user, _ := s.auth.CurrentUser(r)

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len(name) > 40 {
		s.flashAndRedirect(w, r, "Device name is required (max 40 chars).")
		return
	}

	group := s.allocator.GroupForUserGroups(user.Groups, s.cfg.Default)
	if group == "" {
		s.flashAndRedirect(w, r, "Your OIDC groups don't match any configured group.")
		return
	}

	used, err := s.store.UsedIPs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ip, err := s.allocator.Allocate(group, used)
	if err != nil {
		s.flashAndRedirect(w, r, "Address allocation failed: "+err.Error())
		return
	}

	kp, err := wg.NewKeypair()
	if err != nil {
		http.Error(w, "keygen: "+err.Error(), http.StatusInternalServerError)
		return
	}

	dev := &store.Device{
		UserID: user.ID, Name: name,
		PublicKey: kp.Public, IP: ip, GroupAtCreation: group,
	}
	id, err := s.store.CreateDevice(r.Context(), dev)
	if err != nil {
		http.Error(w, "create device: "+err.Error(), http.StatusInternalServerError)
		return
	}
	dev.ID = id

	if err := s.applyPeers(r); err != nil {
		http.Error(w, "apply wg peers: "+err.Error(), http.StatusInternalServerError)
		return
	}

	conf, err := render.WireguardConf(render.ClientConfigInput{
		PrivateKey:      kp.Private,
		Address:         ip,
		DNS:             s.cfg.WireGuard.Users.DNS,
		ServerPublicKey: s.wg.UsersPublicKey(),
		Endpoint:        s.cfg.WireGuard.Users.Endpoint,
		AllowedIPs:      s.cfg.WireGuard.Users.AllowedIPs,
	})
	if err != nil {
		http.Error(w, "render conf: "+err.Error(), http.StatusInternalServerError)
		return
	}
	qr, err := render.QRDataURI(conf)
	if err != nil {
		http.Error(w, "render qr: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.render(w, r, "device_created.html", createdData{
		baseData: baseData{User: user},
		Device:   dev,
		Conf:     conf,
		ConfB64:  base64.StdEncoding.EncodeToString([]byte(conf)),
		QR:       qr,
	})
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	user, _ := s.auth.CurrentUser(r)
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteDevice(r.Context(), user.ID, id); err != nil {
		if errors.Is(err, http.ErrNoCookie) || err.Error() == "sql: no rows in result set" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.applyPeers(r); err != nil {
		http.Error(w, "apply wg peers: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.session.Put(r.Context(), flashKey, "Device revoked.")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) applyPeers(r *http.Request) error {
	all, err := s.store.ListAllDevices(r.Context())
	if err != nil {
		return err
	}
	peers := make([]wg.UserPeer, 0, len(all))
	for _, d := range all {
		peers = append(peers, wg.UserPeer{PublicKey: d.PublicKey, IP: d.IP})
	}
	return s.wg.Apply(peers)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	tpl, ok := s.pages[name]
	if !ok {
		http.Error(w, "unknown template: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) flashAndRedirect(w http.ResponseWriter, r *http.Request, msg string) {
	s.session.Put(r.Context(), flashKey, msg)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) popFlash(r *http.Request) string {
	v := s.session.GetString(r.Context(), flashKey)
	if v != "" {
		s.session.Remove(r.Context(), flashKey)
	}
	return v
}
