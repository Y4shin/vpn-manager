package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/patric/vpn-manager/internal/mockidp"
)

func main() {
	listen := flag.String("listen", ":8081", "listen address")
	issuer := flag.String("issuer", "http://localhost:8081", "issuer URL")
	usersFile := flag.String("users-file", "/etc/mock-idp/users.yaml", "users config")
	flag.Parse()

	cfg, err := loadConfig(*usersFile)
	if err != nil {
		log.Fatalf("load users: %v", err)
	}
	s, err := mockidp.New(*issuer, cfg)
	if err != nil {
		log.Fatalf("mockidp: %v", err)
	}
	log.Printf("mock-idp issuer=%s listen=%s users=%d", *issuer, *listen, len(cfg.Users))
	if err := http.ListenAndServe(*listen, s.Handler()); err != nil {
		log.Fatal(err)
	}
}

func loadConfig(path string) (mockidp.Config, error) {
	var c mockidp.Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return c, fmt.Errorf("client_id and client_secret are required")
	}
	return c, nil
}
