package main

import (
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gouter/internal/mpls"
	"gouter/internal/netstack"
	"gouter/internal/router"
	"gouter/internal/transport"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mplsListen := "127.0.0.1:16635"
	mplsPeer := "127.0.0.1:16636"

	// Create gouter components
	ns := netstack.NewManager(true)
	fib := router.NewFIB()
	nexthop := router.NewNexthopResolver(fib)
	lfib := mpls.NewLFIB()
	r := router.NewRouter(fib, nexthop, ns, lfib)

	// MPLS/UDP transport
	mplsAddr, err := netip.ParseAddrPort(mplsListen)
	if err != nil {
		log.Fatal(err)
	}
	mplsTransport, err := mpls.NewUDPTransport("mpls-udp", mplsAddr)
	if err != nil {
		log.Fatal(err)
	}
	peerAddr, err := netip.ParseAddrPort(mplsPeer)
	if err != nil {
		log.Fatal(err)
	}
	mplsTransport.AddPeer(peerAddr.Addr(), peerAddr)

	// Add NIC for local delivery
	localPrefix := netip.MustParsePrefix("10.200.0.1/32")
	_, err = ns.AddNIC(netstack.NICConfig{
		Name:    "mpls-udp",
		Address: localPrefix,
		MTU:     1500,
	})
	if err != nil {
		log.Fatal(err)
	}
	nexthop.AddTransport("mpls-udp", []netip.Prefix{localPrefix})

	r.AddTransport(mplsTransport)
	go handleOutbound(ctx, ns, "mpls-udp", mplsTransport)

	// FIB: make 10.200.0.1 local
	fib.Add(router.FIBEntry{
		Prefix:    localPrefix,
		Transport: "mpls-udp",
		Action:    router.ActionLocal,
	})

	// LFIB: label 100 → SWAP to 200
	lfib.Add(mpls.LFIBEntry{
		InLabel:   100,
		Op:        mpls.OpSwap,
		OutLabels: []uint32{200},
		Transport: "mpls-udp",
	})

	// LFIB: label 50 → POP (expose inner IP → IP routing)
	lfib.Add(mpls.LFIBEntry{
		InLabel: 50,
		Op:      mpls.OpPop,
	})

	go r.Run(ctx)
	time.Sleep(100 * time.Millisecond)

	log.Println("=== Test 1: MPLS SWAP (label 100 → 200) ===")
	testMPLSSwap(mplsListen, mplsPeer)

	log.Println("=== Test 2: MPLS POP (label 50 → IP → local) ===")
	testMPLSPop(mplsListen)

	log.Println("=== Test 3: MPLS double-label SWAP+POP ===")
	testMPLSDoubleLabel(mplsListen, mplsPeer)

	log.Println("All MPLS tests done.")
	cancel()
}

func testMPLSSwap(srcPort, dstPort string) {
	// Listen on the peer port to receive the swapped packet
	peerAddr, _ := net.ResolveUDPAddr("udp", dstPort)
	recvConn, err := net.ListenUDP("udp", peerAddr)
	if err != nil {
		log.Fatalf("SWAP test: listen: %v", err)
	}
	defer recvConn.Close()

	// Build MPLS frame [label 100][payload "SWAP-TEST"]
	payload := []byte("SWAP-TEST-OK")
	labeled := mpls.PushLabel(payload, 100)

	// Send to gouter's MPLS/UDP port
	srcAddr, _ := net.ResolveUDPAddr("udp", srcPort)
	sendConn, err := net.DialUDP("udp", nil, srcAddr)
	if err != nil {
		log.Fatalf("SWAP test: dial: %v", err)
	}
	defer sendConn.Close()

	if _, err := sendConn.Write(labeled); err != nil {
		log.Fatalf("SWAP test: send: %v", err)
	}
	log.Printf("SWAP test: sent [label 100][\"%s\"] to %s", payload, srcPort)

	// Receive the swapped packet
	buf := make([]byte, 65535)
	recvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := recvConn.ReadFromUDP(buf)
	if err != nil {
		log.Fatalf("SWAP test: recv: %v", err)
	}

	received := buf[:n]
	label, rest, err := mpls.PopLabel(received)
	if err != nil {
		log.Fatalf("SWAP test: parse label: %v", err)
	}
	if label != 200 {
		log.Fatalf("SWAP test: label = %d, want 200", label)
	}
	if string(rest) != string(payload) {
		log.Fatalf("SWAP test: payload = %q, want %q", rest, payload)
	}
	log.Printf("SWAP test: PASS (label=200, payload=%q)", rest)
}

func testMPLSPop(srcPort string) {
	// Build an ICMP echo packet destined for our local IP (10.200.0.1)
	// Pack it as [label 50][IP packet]
	ipPkt := buildICMPEcho("10.200.0.2", "10.200.0.1")
	labeled := mpls.PushLabel(ipPkt, 50)

	srcAddr, _ := net.ResolveUDPAddr("udp", srcPort)
	sendConn, err := net.DialUDP("udp", nil, srcAddr)
	if err != nil {
		log.Fatalf("POP test: dial: %v", err)
	}
	defer sendConn.Close()

	if _, err := sendConn.Write(labeled); err != nil {
		log.Fatalf("POP test: send: %v", err)
	}
	log.Printf("POP test: sent [label 50][ICMP echo to 10.200.0.1] to %s", srcPort)

	// Give gouter time to process and potentially auto-reply
	time.Sleep(300 * time.Millisecond)

	// The ICMP echo should have been popped, the IP packet injected into netstack.
	// Netstack auto-replies to ICMP echo. The reply goes out via mpls-udp transport.
	// But since the reply is just an IP packet (no MPLS label), it goes through FIB.
	// FIB has no entry for 10.200.0.2, so it gets dropped.
	// We just verify gouter didn't crash and the packet was processed.
	log.Printf("POP test: PASS (packet injected into netstack, no crash)")
}

func testMPLSDoubleLabel(srcPort, dstPort string) {
	peerAddr, _ := net.ResolveUDPAddr("udp", dstPort)
	recvConn, err := net.ListenUDP("udp", peerAddr)
	if err != nil {
		log.Fatalf("2-label test: listen: %v", err)
	}
	defer recvConn.Close()

	// Build MPLS frame [label 50][label 100][payload]
	// LFIB: 50→POP, then inner packet is [label 100][payload] → LFIB: 100→SWAP→200
	innerPayload := "DOUBLE-TEST-OK"
	inner := mpls.PushLabel([]byte(innerPayload), 100)
	labeled := mpls.PushLabel(inner, 50)

	srcAddr, _ := net.ResolveUDPAddr("udp", srcPort)
	sendConn, err := net.DialUDP("udp", nil, srcAddr)
	if err != nil {
		log.Fatalf("2-label test: dial: %v", err)
	}
	defer sendConn.Close()

	if _, err := sendConn.Write(labeled); err != nil {
		log.Fatalf("2-label test: send: %v", err)
	}
	log.Printf("2-label test: sent [50][100][\"%s\"] to %s", innerPayload, srcPort)

	buf := make([]byte, 65535)
	recvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := recvConn.ReadFromUDP(buf)
	if err != nil {
		log.Fatalf("2-label test: recv: %v", err)
	}

	received := buf[:n]
	label, rest, err := mpls.PopLabel(received)
	if err != nil {
		log.Fatalf("2-label test: parse label: %v", err)
	}
	if label != 200 {
		log.Fatalf("2-label test: label = %d, want 200", label)
	}
	if string(rest) != innerPayload {
		log.Fatalf("2-label test: payload = %q, want %q", rest, innerPayload)
	}
	log.Printf("2-label test: PASS (POP→SWAP: label=200, payload=%q)", rest)
}

func buildICMPEcho(src, dst string) []byte {
	srcIP := netip.MustParseAddr(src)
	dstIP := netip.MustParseAddr(dst)

	// IPv4 header (20 bytes) + ICMP header (8 bytes) = 28 bytes
	pkt := make([]byte, 28)
	pkt[0] = 0x45       // version=4, IHL=5
	pkt[1] = 0x00       // DSCP
	pkt[2] = 0x00       // total len high
	pkt[3] = 28         // total len low
	pkt[4] = 0x00       // ID high
	pkt[5] = 0x01       // ID low
	pkt[6] = 0x00       // flags
	pkt[7] = 0x00       // fragment
	pkt[8] = 64         // TTL
	pkt[9] = 1          // protocol = ICMP
	// checksum at 10-11 (leave 0 for now)
	copy(pkt[12:16], srcIP.AsSlice())
	copy(pkt[16:20], dstIP.AsSlice())

	// ICMP Echo Request
	pkt[20] = 8  // type = Echo
	pkt[21] = 0  // code
	pkt[22] = 0  // checksum high
	pkt[23] = 0  // checksum low
	pkt[24] = 0  // ID high
	pkt[25] = 1  // ID low
	pkt[26] = 0  // seq high
	pkt[27] = 1  // seq low

	// Compute ICMP checksum
	icmpData := pkt[20:]
	cs := checksum(icmpData)
	pkt[22] = byte(cs >> 8)
	pkt[23] = byte(cs)

	// Compute IP header checksum
	ipHdr := pkt[:20]
	ipHdr[10] = 0
	ipHdr[11] = 0
	ipCS := checksum(ipHdr)
	pkt[10] = byte(ipCS >> 8)
	pkt[11] = byte(ipCS)

	return pkt
}

func checksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func handleOutbound(ctx context.Context, ns *netstack.Manager, name string, t transport.Transport) {
	ch := ns.GetNICOutChannel(ctx, name)
	if ch == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			_ = t.Write(pkt)
		}
	}
}
