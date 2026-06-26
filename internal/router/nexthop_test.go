package router

import (
	"net/netip"
	"testing"
)

func TestNexthopResolveDirect(t *testing.T) {
	fib := NewFIB()
	resolver := NewNexthopResolver(fib)

	resolver.AddTransport("wg-a", []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
	})

	name, found := resolver.Resolve(netip.MustParseAddr("10.0.1.100"))
	if !found {
		t.Fatal("next-hop not resolved")
	}
	if name != "wg-a" {
		t.Errorf("transport = %s, want wg-a", name)
	}
}

func TestNexthopResolveByFIB(t *testing.T) {
	fib := NewFIB()
	resolver := NewNexthopResolver(fib)

	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.0.2.0/24"),
		NextHop:   netip.MustParseAddr("10.0.2.1"),
		Transport: "wg-b",
		Action:    ActionForward,
	})

	name, found := resolver.Resolve(netip.MustParseAddr("10.0.2.1"))
	if !found {
		t.Fatal("next-hop not resolved via FIB")
	}
	if name != "wg-b" {
		t.Errorf("transport = %s, want wg-b", name)
	}
}

func TestNexthopResolvePreferDirect(t *testing.T) {
	fib := NewFIB()
	resolver := NewNexthopResolver(fib)

	resolver.AddTransport("wg-a", []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
	})
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.0.1.0/24"),
		Transport: "wg-other",
		Action:    ActionForward,
	})

	name, found := resolver.Resolve(netip.MustParseAddr("10.0.1.50"))
	if !found {
		t.Fatal("next-hop not resolved")
	}
	if name != "wg-a" {
		t.Errorf("transport = %s, want wg-a (direct should take priority)", name)
	}
}

func TestNexthopResolveNotFound(t *testing.T) {
	fib := NewFIB()
	resolver := NewNexthopResolver(fib)

	_, found := resolver.Resolve(netip.MustParseAddr("1.2.3.4"))
	if found {
		t.Error("should not find unknown next-hop")
	}
}

func TestNexthopRemoveTransport(t *testing.T) {
	fib := NewFIB()
	resolver := NewNexthopResolver(fib)

	resolver.AddTransport("wg-a", []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
	})
	resolver.RemoveTransport("wg-a")

	_, found := resolver.Resolve(netip.MustParseAddr("10.0.1.1"))
	if found {
		t.Error("should not resolve after transport removed")
	}
}

func TestNexthopResolveTransport(t *testing.T) {
	fib := NewFIB()
	resolver := NewNexthopResolver(fib)

	resolver.AddTransport("wg-a", []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
	})

	name, nh, found := resolver.ResolveTransport(netip.MustParseAddr("10.0.1.100"))
	if !found {
		t.Fatal("not resolved")
	}
	if name != "wg-a" {
		t.Errorf("transport = %s", name)
	}
	if nh.String() != "10.0.1.100" {
		t.Errorf("direct nexthop = %s, want 10.0.1.100", nh)
	}
}

func TestNexthopResolveTransportViaFIB(t *testing.T) {
	fib := NewFIB()
	resolver := NewNexthopResolver(fib)

	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("192.168.0.0/16"),
		NextHop:   netip.MustParseAddr("10.0.1.1"),
		Transport: "wg-b",
		Action:    ActionForward,
	})

	_, nh, found := resolver.ResolveTransport(netip.MustParseAddr("192.168.1.1"))
	if !found {
		t.Fatal("not resolved")
	}
	if nh.String() != "10.0.1.1" {
		t.Errorf("resolved nexthop = %s, want 10.0.1.1", nh)
	}
}

func TestNexthopMultipleTransports(t *testing.T) {
	fib := NewFIB()
	resolver := NewNexthopResolver(fib)

	resolver.AddTransport("wg-a", []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")})
	resolver.AddTransport("wg-b", []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")})
	resolver.AddTransport("mpls-udp", []netip.Prefix{netip.MustParsePrefix("10.255.0.0/16")})

	tests := []struct {
		addr string
		want string
	}{
		{"10.0.1.1", "wg-a"},
		{"10.0.2.1", "wg-b"},
		{"10.255.1.1", "mpls-udp"},
	}

	for _, tt := range tests {
		name, found := resolver.Resolve(netip.MustParseAddr(tt.addr))
		if !found {
			t.Errorf("%s: not resolved", tt.addr)
			continue
		}
		if name != tt.want {
			t.Errorf("%s: transport = %s, want %s", tt.addr, name, tt.want)
		}
	}
}
