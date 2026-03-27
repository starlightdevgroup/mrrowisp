package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"mrrowisp/wisp"
)

type Config struct {
	Port                  string `json:"port"`
	DisableUDP            bool   `json:"disableUDP"`
	TcpBufferSize         int    `json:"tcpBufferSize"`
	BufferRemainingLength uint32 `json:"bufferRemainingLength"`
	TcpNoDelay            bool   `json:"tcpNoDelay"`
	WebsocketTcpNoDelay   bool   `json:"websocketTcpNoDelay"`
	Blacklist             struct {
		Hostnames []string `json:"hostnames"`
	} `json:"blacklist"`
	Whitelist struct {
		Hostnames []string `json:"hostnames"`
	} `json:"whitelist"`
	Proxy                      string `json:"proxy"`
	WebsocketPermessageDeflate bool   `json:"websocketPermessageDeflate"`
	DnsServer                  string `json:"dnsServer"`
	EnableTwisp                bool   `json:"enableTwisp"`

	EnableV2             bool              `json:"enableV2"`
	Motd                 string            `json:"motd"`
	PasswordAuth         bool              `json:"passwordAuth"`
	PasswordAuthRequired bool              `json:"passwordAuthRequired"`
	PasswordUsers        map[string]string `json:"passwordUsers"`
	CertAuth             bool              `json:"certAuth"`
	CertAuthRequired     bool              `json:"certAuthRequired"`
	CertAuthPublicKeys   []string          `json:"certAuthPublicKeys"`
	EnableStreamConfirm  bool              `json:"enableStreamConfirm"`
}

func loadConfig(filename string) (Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func createWispConfig(cfg Config) *wisp.Config {
	blacklistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Blacklist.Hostnames {
		blacklistedHostnames[host] = struct{}{}
	}

	whitelistedHostnames := make(map[string]struct{})
	for _, host := range cfg.Whitelist.Hostnames {
		whitelistedHostnames[host] = struct{}{}
	}

	var pubKeys []ed25519.PublicKey
	for _, hexKey := range cfg.CertAuthPublicKeys {
		hexKeyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			fmt.Printf("warning: invalid public key hex %q: %v\n", hexKey, err)
			continue
		}
		if len(hexKeyBytes) != ed25519.PublicKeySize {
			fmt.Printf("warning: public key %q has invalid length %d (expected %d)\n", hexKey, len(hexKeyBytes), ed25519.PublicKeySize)
			continue
		}
		pubKeys = append(pubKeys, ed25519.PublicKey(hexKeyBytes))
	}

	return &wisp.Config{
		DisableUDP:            cfg.DisableUDP,
		TcpBufferSize:         cfg.TcpBufferSize,
		BufferRemainingLength: cfg.BufferRemainingLength,
		TcpNoDelay:            cfg.TcpNoDelay,
		WebsocketTcpNoDelay:   cfg.WebsocketTcpNoDelay,
		Blacklist: struct {
			Hostnames map[string]struct{}
		}{
			Hostnames: blacklistedHostnames,
		},
		Whitelist: struct {
			Hostnames map[string]struct{}
		}{
			Hostnames: whitelistedHostnames,
		},
		Proxy:                      cfg.Proxy,
		WebsocketPermessageDeflate: cfg.WebsocketPermessageDeflate,
		DnsServer:                  cfg.DnsServer,
		EnableTwisp:                cfg.EnableTwisp,
		EnableV2:                   cfg.EnableV2,
		Motd:                       cfg.Motd,
		PasswordAuth:               cfg.PasswordAuth,
		PasswordAuthRequired:       cfg.PasswordAuthRequired,
		PasswordUsers:              cfg.PasswordUsers,
		CertAuth:                   cfg.CertAuth,
		CertAuthRequired:           cfg.CertAuthRequired,
		CertAuthPublicKeys:         pubKeys,
		EnableStreamConfirm:        cfg.EnableStreamConfirm,
	}
}

func main() {
	cfg, err := loadConfig("config.json")
	if err != nil {
		fmt.Printf("failed to load config: %v", err)
		return
	}
	wispConfig := createWispConfig(cfg)

	wispHandler := wisp.CreateWispHandler(wispConfig)

	http.HandleFunc("/", wispHandler)
	fmt.Printf("starting wisp server on port %s. . .", cfg.Port)
	err = http.ListenAndServe(":"+cfg.Port, nil)
	if err != nil {
		fmt.Printf("failed to start server: %v", err)
	}
}
