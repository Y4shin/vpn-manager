// login-and-fetch performs the OIDC login flow against the mock-idp, then
// either creates a device (printing the WireGuard config to stdout) or
// deletes one by ID. Used inside the e2e client containers.
package main

import (
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	vps := flag.String("vps", "http://vps:8080", "vpn-manager base URL")
	user := flag.String("user", "", "user to log in as")
	createName := flag.String("create", "", "create a device with this name")
	deleteID := flag.Int64("delete", 0, "delete the device with this ID")
	flag.Parse()

	if *user == "" {
		log.Fatal("--user is required")
	}
	if (*createName == "" && *deleteID == 0) || (*createName != "" && *deleteID != 0) {
		log.Fatal("exactly one of --create or --delete is required")
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasSuffix(req.URL.Path, "/authorize") {
				q := req.URL.Query()
				q.Set("user", *user)
				req.URL.RawQuery = q.Encode()
			}
			if len(via) > 20 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get(*vps + "/auth/login")
	if err != nil {
		log.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/" {
		log.Fatalf("login did not land at /: %s (status %d)", resp.Request.URL.String(), resp.StatusCode)
	}

	if *deleteID != 0 {
		resp, err = client.PostForm(*vps+"/devices/"+strconv.FormatInt(*deleteID, 10)+"/delete", nil)
		if err != nil {
			log.Fatalf("delete: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			log.Fatalf("delete status %d", resp.StatusCode)
		}
		return
	}

	resp, err = client.PostForm(*vps+"/devices", url.Values{"name": []string{*createName}})
	if err != nil {
		log.Fatalf("create device: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("POST /devices status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	confM := regexp.MustCompile(`(?s)<pre class="conf">(.*?)</pre>`).FindStringSubmatch(string(body))
	if confM == nil {
		log.Fatalf("response missing config block")
	}

	// Find the device ID from a follow-up GET / (it appears in the delete form action).
	dashResp, err := client.Get(*vps + "/")
	if err != nil {
		log.Fatal(err)
	}
	dashBody, _ := io.ReadAll(dashResp.Body)
	dashResp.Body.Close()
	idM := regexp.MustCompile(`/devices/(\d+)/delete`).FindStringSubmatch(string(dashBody))
	if idM == nil {
		log.Fatalf("dashboard missing delete-form for new device")
	}

	fmt.Fprintf(os.Stdout, "DEVICE_ID=%s\n", idM[1])
	fmt.Fprint(os.Stdout, strings.TrimSpace(html.UnescapeString(confM[1]))+"\n")
}
