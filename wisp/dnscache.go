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
}

type DNSCache struct {
	resolver *net.Resolver
	ttl      time.Duration

	mu    sync.RWMutex
	cache map[string]dnsEntry
}

func NewDNSCache(resolver *net.Resolver, ttl time.Duration) *DNSCache {
	return &DNSCache{
		resolver: resolver,
		ttl:      ttl,
		cache:    make(map[string]dnsEntry),
	}
}

func (d *DNSCache) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	now := time.Now()

	d.mu.RLock()
	entry, ok := d.cache[host]
	d.mu.RUnlock()

	if ok && now.Before(entry.expiresAt) {
		return entry.ips, nil
	}

	ips, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.cache[host] = dnsEntry{
		ips:       ips,
		expiresAt: now.Add(d.ttl),
	}
	d.mu.Unlock()

	return ips, nil
}
