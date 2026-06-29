package bgp

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"gouter/internal/netstack"
)

func TestProxyManagerCreateProxy(t *testing.T) {
	ns := netstack.NewManager()
	pm := NewProxyManager(ns, 179, netip.Addr{}, 0)
	defer pm.Close()

	peerAddr := netip.MustParseAddr("10.0.1.2")
	proxy, err := pm.CreateProxy("test-peer", peerAddr, 179)
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}

	if proxy.Name != "test-peer" {
		t.Errorf("name = %s", proxy.Name)
	}
	if proxy.PeerAddr != peerAddr {
		t.Errorf("peer = %s", proxy.PeerAddr)
	}
	if proxy.LocalIP != netip.MustParseAddr("127.0.0.2") {
		t.Errorf("local = %s", proxy.LocalIP)
	}
	if proxy.OutboundPort == 0 {
		t.Errorf("port = 0, want non-zero")
	}

	same, err := pm.CreateProxy("test-peer", peerAddr, 179)
	if err != nil {
		t.Fatalf("CreateProxy again: %v", err)
	}
	if same.LocalIP != proxy.LocalIP {
		t.Error("duplicate proxy should return same")
	}
}

func TestProxyManagerMultiplePeers(t *testing.T) {
	ns := netstack.NewManager()
	pm := NewProxyManager(ns, 179, netip.Addr{}, 0)
	defer pm.Close()

	p1, err := pm.CreateProxy("p1", netip.MustParseAddr("10.0.1.2"), 179)
	if err != nil {
		t.Fatalf("p1: %v", err)
	}
	p2, err := pm.CreateProxy("p2", netip.MustParseAddr("10.0.2.2"), 179)
	if err != nil {
		t.Fatalf("p2: %v", err)
	}
	p3, err := pm.CreateProxy("p3", netip.MustParseAddr("10.0.3.2"), 179)
	if err != nil {
		t.Fatalf("p3: %v", err)
	}

	if p1.LocalIP != netip.MustParseAddr("127.0.0.2") {
		t.Errorf("p1 = %s", p1.LocalIP)
	}
	if p2.LocalIP != netip.MustParseAddr("127.0.0.3") {
		t.Errorf("p2 = %s", p2.LocalIP)
	}
	if p3.LocalIP != netip.MustParseAddr("127.0.0.4") {
		t.Errorf("p3 = %s", p3.LocalIP)
	}
	if p1.OutboundPort == 0 || p2.OutboundPort == 0 || p3.OutboundPort == 0 {
		t.Errorf("ports: %d %d %d (all should be non-zero)", p1.OutboundPort, p2.OutboundPort, p3.OutboundPort)
	}

	if pm.GetProxy(netip.MustParseAddr("10.0.2.2")) != p2 {
		t.Error("GetProxy failed")
	}
	if pm.GetProxy(netip.MustParseAddr("1.2.3.4")) != nil {
		t.Error("GetProxy should return nil for unknown")
	}
}

func TestProxyManagerListener(t *testing.T) {
	ns := netstack.NewManager()
	pm := NewProxyManager(ns, 179, netip.Addr{}, 0)
	defer pm.Close()

	proxy, err := pm.CreateProxy("test-peer", netip.MustParseAddr("10.0.1.2"), 179)
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}

	addr := "127.0.0.2:" + strconv.Itoa(int(proxy.OutboundPort))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("connect to proxy %s: %v", addr, err)
	}
	conn.Close()
	time.Sleep(10 * time.Millisecond)
}
