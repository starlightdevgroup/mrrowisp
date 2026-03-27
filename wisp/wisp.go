package wisp

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/lxzan/gws"
)

type Config struct {
	DisableUDP            bool
	TcpBufferSize         int
	BufferRemainingLength uint32
	TcpNoDelay            bool
	WebsocketTcpNoDelay   bool
	Blacklist             struct {
		Hostnames map[string]struct{}
	}
	Whitelist struct {
		Hostnames map[string]struct{}
	}
	Proxy                      string
	WebsocketPermessageDeflate bool
	DnsServer                  string
	EnableTwisp                bool

	EnableV2             bool
	Motd                 string
	PasswordAuth         bool
	PasswordAuthRequired bool
	PasswordUsers        map[string]string
	CertAuth             bool
	CertAuthRequired     bool
	CertAuthPublicKeys   []ed25519.PublicKey
	EnableStreamConfirm  bool

	DNSCache *DNSCache

	ReadBufPool sync.Pool

	Dialer net.Dialer
}

func (c *Config) InitResolver() {
	if c.DnsServer != "" {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", c.DnsServer)
			},
		}
		c.DNSCache = NewDNSCache(resolver, 5*time.Minute)
	}
}

type upgradeHandler struct {
	gws.BuiltinEventHandler
}

func CreateWispHandler(config *Config) http.HandlerFunc {
	config.InitResolver()

	readBufSize := 15 + config.TcpBufferSize
	config.ReadBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, readBufSize)
			return &buf
		},
	}

	config.Dialer = net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	upgrader := gws.NewUpgrader(&upgradeHandler{}, &gws.ServerOption{
		PermessageDeflate: gws.PermessageDeflate{
			Enabled: config.WebsocketPermessageDeflate,
		},
	})

	return func(w http.ResponseWriter, r *http.Request) {
		useV2 := config.EnableV2 && r.Header.Get("Sec-WebSocket-Protocol") != ""

		wsConn, err := upgrader.Upgrade(w, r)
		if err != nil {
			return
		}

		netConn := wsConn.NetConn()

		if tc, ok := netConn.(*net.TCPConn); ok {
			if config.WebsocketTcpNoDelay {
				tc.SetNoDelay(true)
			}
			tc.SetReadBuffer(1 << 20)
			tc.SetWriteBuffer(1 << 20)
		}

		wc := &wispConnection{
			netConn:      netConn,
			writeCh:      make(chan writeReq, 4096), // funny number
			config:       config,
			twispStreams: newTwisp(),
			isV2:         useV2,
		}

		go wc.writeLoop()

		if useV2 {
			go wc.v2Handshake()
		} else {
			wc.sendPacket(0, config.BufferRemainingLength)
			go wc.readLoop()
		}
	}
}
