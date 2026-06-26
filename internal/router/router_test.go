package router

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"gouter/internal/mpls"
	"gouter/internal/netstack"
	"gouter/internal/transport"
)

func TestRouterIPForwarding(t *testing.T) {
	ns := netstack.NewManager()
	fib := NewFIB()
	nexthop := NewNexthopResolver(fib)
	lfib := mpls.NewLFIB()
	r := NewRouter(fib, nexthop, ns, lfib)

	fake := newFakeTransport("wg-b")
	r.AddTransport(fake)

	// Add NIC for fake transport so local address detection works
	_, _ = ns.AddNIC(netstack.NICConfig{
		Name:    "wg-b",
		Address: netip.MustParsePrefix("10.0.2.1/32"),
		MTU:     1500,
	})
	nexthop.AddTransport("wg-b", []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")})

	// Add a route
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.1.0.0/24"),
		NextHop:   netip.MustParseAddr("10.0.2.2"),
		Transport: "wg-b",
		Action:    ActionForward,
	})

	// Build a simple IPv4 packet destined for 10.1.0.1
	ipPkt := buildIPv4Packet("10.0.1.1", "10.1.0.1", 64)

	pkt := transport.Packet{
		Type:      transport.PacketIP,
		Data:      ipPkt,
		Transport: "wg-a",
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go r.Run(ctx)

	// Feed packet through the router by simulating what runTransportReader does
	go func() {
		r.handlePacket(pkt)
	}()

	select {
	case fwd := <-fake.out:
		// Verify packet was forwarded to the correct transport.
		// The Transport field on the packet is the source, not destination.
		// We reached here because f.out received something → forwarding worked.
		_ = fwd
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for forwarded packet")
	}
}

func TestRouterLocalDelivery(t *testing.T) {
	ns := netstack.NewManager()
	fib := NewFIB()
	nexthop := NewNexthopResolver(fib)
	lfib := mpls.NewLFIB()
	r := NewRouter(fib, nexthop, ns, lfib)

	// Add a NIC whose address will be considered local
	nicAddr := netip.MustParsePrefix("10.0.1.1/32")
	_, err := ns.AddNIC(netstack.NICConfig{
		Name:    "wg-a",
		Address: nicAddr,
		MTU:     1500,
	})
	if err != nil {
		t.Fatalf("add nic: %v", err)
	}

	// Ensure the address is seen as local
	if !ns.IsLocalAddress(netip.MustParseAddr("10.0.1.1")) {
		t.Fatal("expected 10.0.1.1 to be local")
	}

	// Build a packet destined for our local address
	ipPkt := buildIPv4Packet("10.0.2.1", "10.0.1.1", 64)

	pkt := transport.Packet{
		Type:      transport.PacketIP,
		Data:      ipPkt,
		Transport: "wg-a",
	}

	r.handlePacket(pkt)
	// If it doesn't panic or error, local delivery succeeded
}

func TestRouterMPLSRouting(t *testing.T) {
	ns := netstack.NewManager()
	fib := NewFIB()
	nexthop := NewNexthopResolver(fib)
	lfib := mpls.NewLFIB()
	r := NewRouter(fib, nexthop, ns, lfib)

	fake := newFakeTransport("mpls-udp")
	r.AddTransport(fake)

	// Add LFIB entry: label 100 → SWAP to 200, forward via mpls-udp
	lfib.Add(mpls.LFIBEntry{
		InLabel:   100,
		Op:        mpls.OpSwap,
		OutLabels: []uint32{200},
		Transport: "mpls-udp",
	})

	// Build MPLS packet: [label 100][IP]
	ipPayload := buildIPv4Packet("10.0.1.1", "10.1.0.1", 64)
	mplsPkt := mpls.PushLabel(ipPayload, 100)

	pkt := transport.Packet{
		Type:      transport.PacketMPLS,
		Data:      mplsPkt,
		Transport: "mpls-udp",
	}

	r.handlePacket(pkt)

	select {
	case fwd := <-fake.out:
		if fwd.Type != transport.PacketMPLS {
			t.Error("forwarded packet should be MPLS type")
		}
		label, _, _ := mpls.PopLabel(fwd.Data)
		if label != 200 {
			t.Errorf("swapped label = %d, want 200", label)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestRouterMPLSPopThenIPForward(t *testing.T) {
	ns := netstack.NewManager()
	fib := NewFIB()
	nexthop := NewNexthopResolver(fib)
	lfib := mpls.NewLFIB()
	r := NewRouter(fib, nexthop, ns, lfib)

	fake := newFakeTransport("wg-b")
	r.AddTransport(fake)
	_, _ = ns.AddNIC(netstack.NICConfig{
		Name:    "wg-b",
		Address: netip.MustParsePrefix("10.0.2.1/32"),
		MTU:     1500,
	})
	nexthop.AddTransport("wg-b", []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")})
	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.1.0.0/24"),
		NextHop:   netip.MustParseAddr("10.0.2.2"),
		Transport: "wg-b",
		Action:    ActionForward,
	})

	// LFIB: label 50 → POP, then IP route
	lfib.Add(mpls.LFIBEntry{
		InLabel: 50,
		Op:      mpls.OpPop,
	})

	// MPLS packet [label 50][IP: dst=10.1.0.1]
	ipPayload := buildIPv4Packet("10.0.1.1", "10.1.0.1", 64)
	mplsPkt := mpls.PushLabel(ipPayload, 50)

	pkt := transport.Packet{
		Type:      transport.PacketMPLS,
		Data:      mplsPkt,
		Transport: "mpls-udp",
	}

	r.handlePacket(pkt)

	select {
	case fwd := <-fake.out:
		if fwd.Type != transport.PacketIP {
			t.Error("forwarded packet should be IP after POP")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestRouterFIBPushMPLS(t *testing.T) {
	ns := netstack.NewManager()
	fib := NewFIB()
	nexthop := NewNexthopResolver(fib)
	lfib := mpls.NewLFIB()
	r := NewRouter(fib, nexthop, ns, lfib)

	fake := newFakeTransport("mpls-udp")
	r.AddTransport(fake)
	nexthop.AddTransport("mpls-udp", []netip.Prefix{netip.MustParsePrefix("10.255.0.0/16")})

	fib.Add(FIBEntry{
		Prefix:    netip.MustParsePrefix("10.1.0.0/24"),
		NextHop:   netip.MustParseAddr("10.255.0.2"),
		Transport: "mpls-udp",
		Action:    ActionPush,
		OutLabels: []uint32{300},
	})

	ipPkt := buildIPv4Packet("10.0.1.1", "10.1.0.1", 64)
	pkt := transport.Packet{
		Type:      transport.PacketIP,
		Data:      ipPkt,
		Transport: "wg-a",
	}

	r.handlePacket(pkt)

	select {
	case fwd := <-fake.out:
		if fwd.Type != transport.PacketMPLS {
			t.Fatal("forwarded packet should be MPLS type after PUSH")
		}
		label, payload, err := mpls.PopLabel(fwd.Data)
		if err != nil {
			t.Fatalf("pop label: %v", err)
		}
		if label != 300 {
			t.Errorf("label = %d, want 300", label)
		}
		_ = payload
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// fakeTransport implements transport.Transport for testing.
// reader chan is for the router's Read() goroutine; out chan captures writes for test assertions.
type fakeTransport struct {
	name   string
	reader chan transport.Packet
	out    chan transport.Packet
}

func newFakeTransport(name string) *fakeTransport {
	return &fakeTransport{
		name:   name,
		reader: make(chan transport.Packet, 10),
		out:    make(chan transport.Packet, 10),
	}
}

func (f *fakeTransport) Name() string                     { return f.name }
func (f *fakeTransport) MTU() int                         { return 1500 }
func (f *fakeTransport) Read() <-chan transport.Packet    { return f.reader }
func (f *fakeTransport) Write(pkt transport.Packet) error { f.out <- pkt; return nil }
func (f *fakeTransport) Close() error                     { return nil }

// buildIPv4Packet creates a minimal IPv4 packet with given src/dst
func buildIPv4Packet(src, dst string, ttl uint8) []byte {
	srcIP := netip.MustParseAddr(src)
	dstIP := netip.MustParseAddr(dst)

	pkt := make([]byte, 20)
	pkt[0] = 0x45          // version=4, IHL=5
	pkt[1] = 0x00          // DSCP+ECN
	pkt[2] = 0x00          // total length (high byte)
	pkt[3] = 20            // total length (low byte)
	pkt[4] = 0x00          // identification
	pkt[5] = 0x01
	pkt[6] = 0x00          // flags + fragment offset
	pkt[7] = 0x00
	pkt[8] = ttl           // TTL
	pkt[9] = 0x06          // protocol (TCP)
	pkt[10] = 0x00         // checksum (leave 0 for test)
	pkt[11] = 0x00
	copy(pkt[12:16], srcIP.AsSlice())
	copy(pkt[16:20], dstIP.AsSlice())
	return pkt
}
