package router

import (
	"net/netip"
)

type NexthopResolver struct {
	fib          *FIB
	transportIPs map[string][]netip.Prefix
}

func NewNexthopResolver(fib *FIB) *NexthopResolver {
	return &NexthopResolver{
		fib:          fib,
		transportIPs: make(map[string][]netip.Prefix),
	}
}

func (r *NexthopResolver) AddTransport(name string, prefixes []netip.Prefix) {
	r.transportIPs[name] = prefixes
}

func (r *NexthopResolver) RemoveTransport(name string) {
	delete(r.transportIPs, name)
}

func (r *NexthopResolver) Resolve(nexthop netip.Addr) (transportName string, found bool) {
	for name, prefixes := range r.transportIPs {
		for _, pfx := range prefixes {
			if pfx.Contains(nexthop) {
				return name, true
			}
		}
	}

	entry := r.fib.Lookup(nexthop)
	if entry != nil {
		return entry.Transport, true
	}
	return "", false
}

func (r *NexthopResolver) ResolveTransport(nexthop netip.Addr) (transportName string, directNextHop netip.Addr, found bool) {
	for name, prefixes := range r.transportIPs {
		for _, pfx := range prefixes {
			if pfx.Contains(nexthop) {
				return name, nexthop, true
			}
		}
	}

	entry := r.fib.Lookup(nexthop)
	if entry != nil {
		return entry.Transport, entry.NextHop, true
	}
	return "", netip.Addr{}, false
}
