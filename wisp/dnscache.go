package wisp

import (
	"context"
	"net"
	"sync"
	"time"
)

type dnsEntry struct {
	ips       []net.IPAddr
	expiresAt time.Time
	err       error
}

type DNSCache struct {
	servers  []string
	resolver *net.Resolver

	mu    sync.RWMutex
	cache map[string]dnsEntry
}

func NewDNSCache(servers []string) *DNSCache {
	cache := &DNSCache{
		servers: servers,
		cache:   make(map[string]dnsEntry),
	}
	cache.initResolver()
	return cache
}

func (d *DNSCache) initResolver() {
	if len(d.servers) > 0 {
		d.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: 5 * time.Second,
				}
				return dialer.DialContext(ctx, "udp", d.servers[0])
			},
		}
	} else {
		d.resolver = net.DefaultResolver
	}
}

func (d *DNSCache) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	now := time.Now()

	d.mu.RLock()
	entry, ok := d.cache[host]
	d.mu.RUnlock()

	if ok && now.Before(entry.expiresAt) {
		if entry.err != nil {
			return nil, entry.err
		}
		return entry.ips, nil
	}

	ips, err := d.resolver.LookupIPAddr(ctx, host)

	d.mu.Lock()
	d.cache[host] = dnsEntry{
		ips:       ips,
		expiresAt: now.Add(120 * time.Second),
		err:       err,
	}
	d.mu.Unlock()

	if err != nil {
		return nil, err
	}

	return ips, nil
}
