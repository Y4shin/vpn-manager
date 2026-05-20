package web_test

import (
	"context"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"

	"github.com/patric/vpn-manager/internal/config"
	"github.com/patric/vpn-manager/internal/ipam"
	"github.com/patric/vpn-manager/internal/mockidp"
	"github.com/patric/vpn-manager/internal/oidc"
	"github.com/patric/vpn-manager/internal/store"
	"github.com/patric/vpn-manager/internal/web"
	"github.com/patric/vpn-manager/internal/wg"
)

type fakeWG struct {
	mu       sync.Mutex
	pubkey   string
	lastApply []wg.UserPeer
}

func (f *fakeWG) UsersPublicKey() string { return f.pubkey }
func (f *fakeWG) Apply(peers []wg.UserPeer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastApply = append([]wg.UserPeer(nil), peers...)
	return nil
}
func (f *fakeWG) Handshakes() (map[string]time.Time, error) {
	return map[string]time.Time{}, nil
}
func (f *fakeWG) peers() []wg.UserPeer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wg.UserPeer(nil), f.lastApply...)
}

type harness struct {
	t          *testing.T
	idpTS      *httptest.Server
	appTS      *httptest.Server
	store      *store.Store
	fakeWG     *fakeWG
	clientFor  func(user string) *http.Client
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	t.Setenv("VPN_TEST_SECRET", "test-secret")

	idpTS := httptest.NewUnstartedServer(http.NotFoundHandler())
	idpTS.Start()
	t.Cleanup(idpTS.Close)
	idp, err := mockidp.New(idpTS.URL, mockidp.Config{
		ClientID:     "vpn-manager",
		ClientSecret: "test-secret",
		Users: []mockidp.User{
			{Sub: "alice", Email: "alice@example.com", Groups: []string{"admins"}},
			{Sub: "bob", Email: "bob@example.com", Groups: []string{"guests"}},
			{Sub: "eve", Email: "eve@example.com", Groups: []string{"nobody"}},
		},
	})
	if err != nil {
		t.Fatalf("mockidp: %v", err)
	}
	idpTS.Config.Handler = idp.Handler()

	appTS := httptest.NewUnstartedServer(http.NotFoundHandler())
	appTS.Start()
	t.Cleanup(appTS.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sm := scs.New()
	sm.Store = sqlite3store.New(st.DB)
	sm.Lifetime = 30 * time.Minute
	sm.Cookie.Secure = false // httptest is http://
	sm.Cookie.SameSite = http.SameSiteLaxMode

	cfg := &config.Config{
		ListenAddr: ":0",
		PublicURL:  appTS.URL,
		DataDir:    t.TempDir(),
		OIDC: config.OIDCConfig{
			Issuer:          idpTS.URL,
			ClientID:        "vpn-manager",
			ClientSecretEnv: "VPN_TEST_SECRET",
			GroupsClaim:     "groups",
			Scopes:          []string{"openid", "email", "profile", "groups"},
		},
		WireGuard: config.WireGuardConfig{
			Users: config.UsersTunnel{
				Interface: "wg-users", ListenPort: 51820,
				Address: "10.100.0.1/16",
				Endpoint: "test-vpn.example.com:51820",
				AllowedIPs: []string{"192.168.1.0/24"},
			},
			Home: config.HomeTunnel{
				Interface: "wg-home", ListenPort: 51821,
				Address: "10.99.0.1/30",
				Peer: config.HomePeer{
					PublicKey:  "ZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2U=",
					AllowedIPs: []string{"10.99.0.2/32", "192.168.1.0/24"},
				},
			},
		},
		Groups: map[string]config.Group{
			"admins": {CIDR: "10.100.10.0/24"},
			"guests": {CIDR: "10.100.30.0/24"},
		},
	}

	authH, err := oidc.New(context.Background(), cfg, st, sm)
	if err != nil {
		t.Fatalf("oidc: %v", err)
	}
	fakeW := &fakeWG{pubkey: "U0VSVkVSUFVCS0VZX0ZBS0U0NDQ0NDQ0NDQ0NDQ0NDA9"}
	alloc, _ := ipam.New(map[string]string{
		"admins": "10.100.10.0/24",
		"guests": "10.100.30.0/24",
	})
	webSrv, err := web.New(cfg, st, authH, sm, fakeW, alloc)
	if err != nil {
		t.Fatalf("web: %v", err)
	}
	appTS.Config.Handler = webSrv.Routes()

	clientFor := func(user string) *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{
			Jar: jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Inject ?user= on the way through the IdP's /authorize.
				if strings.HasPrefix(req.URL.String(), idpTS.URL+"/authorize") {
					q := req.URL.Query()
					q.Set("user", user)
					req.URL.RawQuery = q.Encode()
				}
				if len(via) > 20 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}

	return &harness{t, idpTS, appTS, st, fakeW, clientFor}
}

func (h *harness) login(client *http.Client) {
	h.t.Helper()
	resp, err := client.Get(h.appTS.URL + "/auth/login")
	if err != nil {
		h.t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.Request.URL.Path != "/" {
		h.t.Fatalf("expected to land at /, got %s", resp.Request.URL.String())
	}
	if resp.StatusCode != 200 {
		h.t.Fatalf("login final status %d", resp.StatusCode)
	}
}

var confRE = regexp.MustCompile(`(?s)<pre class="conf">(.*?)</pre>`)

func (h *harness) createDevice(client *http.Client, name string) (conf string, deviceID int64) {
	h.t.Helper()
	resp, err := client.PostForm(h.appTS.URL+"/devices", url.Values{"name": []string{name}})
	if err != nil {
		h.t.Fatalf("post devices: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		h.t.Fatalf("POST /devices status = %d", resp.StatusCode)
	}
	body := readAll(h.t, resp)
	m := confRE.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatalf("response missing <pre class=\"conf\">; body=%s", body)
	}
	conf = strings.TrimSpace(html.UnescapeString(m[1]))
	// Find the device id from a follow-up GET /.
	dashResp, err := client.Get(h.appTS.URL + "/")
	if err != nil {
		h.t.Fatal(err)
	}
	defer dashResp.Body.Close()
	idMatch := regexp.MustCompile(`/devices/(\d+)/delete`).FindStringSubmatch(readAll(h.t, dashResp))
	if idMatch == nil {
		h.t.Fatalf("dashboard missing delete form for new device")
	}
	deviceID, _ = strconv.ParseInt(idMatch[1], 10, 64)
	return conf, deviceID
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(buf)
}

func TestUnauthenticatedRootShowsLogin(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.appTS.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(t, resp)
	if !strings.Contains(body, `href="/auth/login"`) {
		t.Errorf("login page should link to /auth/login; body=%s", body)
	}
}

func TestFullOAuthFlowLandsAtDashboard(t *testing.T) {
	h := newHarness(t)
	client := h.clientFor("alice")
	h.login(client)

	resp, err := client.Get(h.appTS.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(t, resp)
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("dashboard should show alice's email; body=%s", body)
	}
	if !strings.Contains(body, "admins") {
		t.Errorf("dashboard should show group admins; body=%s", body)
	}
}

func TestCreateDeviceAppliesPeerInGroupCIDR(t *testing.T) {
	h := newHarness(t)
	client := h.clientFor("alice")
	h.login(client)

	conf, deviceID := h.createDevice(client, "laptop")
	if deviceID == 0 {
		t.Fatal("expected non-zero device id")
	}
	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
		t.Errorf("conf missing sections:\n%s", conf)
	}
	if !strings.Contains(conf, "10.100.10.") {
		t.Errorf("conf should assign an IP in admins CIDR 10.100.10.0/24:\n%s", conf)
	}

	peers := h.fakeWG.peers()
	if len(peers) != 1 {
		t.Fatalf("fakeWG should have 1 peer after create, has %d", len(peers))
	}
	if !strings.HasPrefix(peers[0].IP, "10.100.10.") {
		t.Errorf("fakeWG peer IP %q not in admins CIDR", peers[0].IP)
	}
}

func TestDeleteDeviceRemovesPeer(t *testing.T) {
	h := newHarness(t)
	client := h.clientFor("alice")
	h.login(client)
	_, id := h.createDevice(client, "laptop")

	resp, err := client.PostForm(h.appTS.URL+"/devices/"+strconv.FormatInt(id, 10)+"/delete", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	if peers := h.fakeWG.peers(); len(peers) != 0 {
		t.Errorf("fakeWG should be empty after delete; got %d peers", len(peers))
	}
}

func TestUserWithoutGroupCannotCreate(t *testing.T) {
	h := newHarness(t)
	client := h.clientFor("eve") // groups: ["nobody"], not configured

	h.login(client)

	resp, err := client.Get(h.appTS.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	dash := readAll(t, resp)
	if !strings.Contains(dash, "aren&#39;t in any configured group") &&
		!strings.Contains(dash, "aren't in any configured group") {
		t.Errorf("expected no-group warning on dashboard; body=%s", dash)
	}
	// The "Add a device" form should be absent.
	if strings.Contains(dash, `name="name"`) {
		t.Errorf("device-create form should be hidden for users without a group")
	}

	// Even if they POST directly, it should fail (no peer created).
	resp2, err := client.PostForm(h.appTS.URL+"/devices", url.Values{"name": []string{"sneaky"}})
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if peers := h.fakeWG.peers(); len(peers) != 0 {
		t.Errorf("no peer should be applied for group-less user; got %d", len(peers))
	}
}
