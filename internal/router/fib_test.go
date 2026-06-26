package router

import (
	"net/netip"
	"testing"
)

func TestFIBAddLookup(t *testing.T) {
	fib := NewFIB()

	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.0.0.0/8"),
		NextHop:   netip.MustParseAddr("192.168.1.1"),
		Transport: "wg-a",
		Action:    ActionForward,
	})

	entry := fib.Lookup(netip.MustParseAddr("10.1.2.3"))
	if entry == nil {
		t.Fatal("route not found")
	}
	if entry.Transport != "wg-a" {
		t.Errorf("transport = %s, want wg-a", entry.Transport)
	}
	if entry.NextHop.String() != "192.168.1.1" {
		t.Errorf("nexthop = %s, want 192.168.1.1", entry.NextHop)
	}
}

func TestFIBLongestMatch(t *testing.T) {
	fib := NewFIB()
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.0.0.0/8"),
		NextHop:   netip.MustParseAddr("10.0.0.1"),
		Transport: "wg-default",
		Action:    ActionForward,
	})
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.1.0.0/16"),
		NextHop:   netip.MustParseAddr("10.1.0.1"),
		Transport: "wg-subnet",
		Action:    ActionForward,
	})
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.1.2.0/24"),
		NextHop:   netip.MustParseAddr("10.1.2.1"),
		Transport: "wg-specific",
		Action:    ActionForward,
	})

	tests := []struct {
		addr      string
		wantTrans string
	}{
		{"10.1.2.55", "wg-specific"},
		{"10.1.3.1", "wg-subnet"},
		{"10.2.0.1", "wg-default"},
	}

	for _, tt := range tests {
		entry := fib.Lookup(netip.MustParseAddr(tt.addr))
		if entry == nil {
			t.Errorf("%s: no route", tt.addr)
			continue
		}
		if entry.Transport != tt.wantTrans {
			t.Errorf("%s: transport = %s, want %s", tt.addr, entry.Transport, tt.wantTrans)
		}
	}
}

func TestFIBLookupMissing(t *testing.T) {
	fib := NewFIB()
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.0.0.0/8"),
		Transport: "wg-a",
		Action:    ActionForward,
	})
	entry := fib.Lookup(netip.MustParseAddr("192.168.1.1"))
	if entry != nil {
		t.Error("expected nil for unmatched address")
	}
}

func TestFIBRemove(t *testing.T) {
	fib := NewFIB()
	pfx := netip.MustParsePrefix("10.0.0.0/8")
	fib.Add(FIBEntry{Prefix: pfx, Transport: "wg-a", Action: ActionForward})
	fib.Remove(pfx)

	entry := fib.Lookup(netip.MustParseAddr("10.1.1.1"))
	if entry != nil {
		t.Error("route should have been removed")
	}
}

func TestFIBUpdate(t *testing.T) {
	fib := NewFIB()
	pfx := netip.MustParsePrefix("10.0.0.0/8")
	fib.Add(FIBEntry{Prefix: pfx, Transport: "wg-a", Action: ActionForward})
	fib.Add(FIBEntry{Prefix: pfx, Transport: "wg-b", Action: ActionForward})

	entry := fib.Lookup(netip.MustParseAddr("10.1.1.1"))
	if entry == nil {
		t.Fatal("route not found")
	}
	if entry.Transport != "wg-b" {
		t.Errorf("transport = %s, want wg-b", entry.Transport)
	}
}

func TestFIBActionPush(t *testing.T) {
	fib := NewFIB()
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.0.0.0/8"),
		NextHop:   netip.MustParseAddr("192.168.1.1"),
		Transport: "mpls-udp",
		Action:    ActionPush,
		OutLabels: []uint32{100, 200},
	})

	entry := fib.Lookup(netip.MustParseAddr("10.1.1.1"))
	if entry == nil {
		t.Fatal("route not found")
	}
	if entry.Action != ActionPush {
		t.Errorf("action = %d, want ActionPush", entry.Action)
	}
	if len(entry.OutLabels) != 2 {
		t.Errorf("labels = %v, want [100,200]", entry.OutLabels)
	}
}

func TestFIBList(t *testing.T) {
	fib := NewFIB()
	fib.Add(FIBEntry{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Transport: "wg-a"})
	fib.Add(FIBEntry{Prefix: netip.MustParsePrefix("192.168.0.0/16"), Transport: "wg-b"})

	list := fib.List()
	if len(list) != 2 {
		t.Errorf("len = %d, want 2", len(list))
	}
}

func TestFIBConcurrency(t *testing.T) {
	fib := NewFIB()
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			fib.Add(FIBEntry{
				Prefix:    netip.MustParsePrefix("10.0.0.0/8"),
				Transport: "wg-a",
				Action:    ActionForward,
			})
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = fib.Lookup(netip.MustParseAddr("10.1.1.1"))
		}
		done <- true
	}()

	<-done
	<-done
}

func TestFIBIPv6(t *testing.T) {
	fib := NewFIB()
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("fd00::/16"),
		NextHop:   netip.MustParseAddr("fe80::1"),
		Transport: "wg-v6",
		Action:    ActionForward,
	})

	entry := fib.Lookup(netip.MustParseAddr("fd00:1234::1"))
	if entry == nil {
		t.Fatal("IPv6 route not found")
	}
	if entry.Transport != "wg-v6" {
		t.Errorf("transport = %s, want wg-v6", entry.Transport)
	}
}
