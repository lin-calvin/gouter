package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gouter/internal/bgp"
	"gouter/internal/config"
	"gouter/internal/mpls"
	"gouter/internal/netstack"
	"gouter/internal/router"
	"gouter/internal/transport"
	"gouter/internal/wg"

	"golang.zx2c4.com/wireguard/device"
)

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ns := netstack.NewManager()
	fib := router.NewFIB()
	nexthop := router.NewNexthopResolver(fib)
	lfib := mpls.NewLFIB()
	r := router.NewRouter(fib, nexthop, ns, lfib)

	// MPLS/UDP transport
	if cfg.MPLS != nil && cfg.MPLS.UDP.ListenPort > 0 {
		mplsAddr := netip.AddrPortFrom(
			netip.MustParseAddr("0.0.0.0"),
			uint16(cfg.MPLS.UDP.ListenPort),
		)
		mplsT, err := mpls.NewUDPTransport("mpls-udp", mplsAddr)
		if err != nil {
			log.Fatalf("mpls: %v", err)
		}
		for _, peer := range cfg.MPLS.UDP.Peers {
			peerAddr, err := netip.ParseAddrPort(peer)
			if err != nil {
				log.Printf("mpls: bad peer %s: %v", peer, err)
				continue
			}
			mplsT.AddPeer(peerAddr.Addr(), peerAddr)
		}
		mplsNIC := netip.MustParsePrefix("10.255.255.1/32")
		_, _ = ns.AddNIC(netstack.NICConfig{
			Name: "mpls-udp", Address: mplsNIC, MTU: 1500,
		})
		nexthop.AddTransport("mpls-udp", []netip.Prefix{mplsNIC})
		r.AddTransport(mplsT)
		go handleOutbound(ctx, ns, "mpls-udp", mplsT)
		log.Printf("mpls/udp on :%d, peers=%d", cfg.MPLS.UDP.ListenPort, len(cfg.MPLS.UDP.Peers))
	}

	// WireGuard transports
	for _, wgCfg := range cfg.WireGuard {
		t := wg.NewTransport(wgCfg.Name, wgCfg.MTU, device.LogLevelError)

		skHex, err := config.B64ToHex(wgCfg.PrivateKey)
		if err != nil {
			log.Fatalf("%s: bad private key: %v", wgCfg.Name, err)
		}

		uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\n",
			skHex, wgCfg.ListenPort)
		for _, p := range wgCfg.Peers {
			pkHex, err := config.B64ToHex(p.PublicKey)
			if err != nil {
				log.Fatalf("%s: bad peer public key: %v", wgCfg.Name, err)
			}
			uapi += fmt.Sprintf("public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n",
				pkHex, p.Endpoint, p.AllowedIPs)
		}

		if err := t.Configure(uapi); err != nil {
			log.Printf("%s: configure: %v", wgCfg.Name, err)
		}

		addrPrefix, err := netip.ParsePrefix(wgCfg.Address)
		if err != nil {
			log.Fatalf("%s: bad address: %v", wgCfg.Name, err)
		}
		_, err = ns.AddNIC(netstack.NICConfig{
			Name: wgCfg.Name, Address: addrPrefix, MTU: 1500,
		})
		if err != nil {
			log.Fatalf("add nic %s: %v", wgCfg.Name, err)
		}
		nexthop.AddTransport(wgCfg.Name, []netip.Prefix{addrPrefix})

		for _, peer := range wgCfg.Peers {
			peerPrefix, err := netip.ParsePrefix(peer.AllowedIPs)
			if err != nil {
				log.Printf("%s: bad allowed_ip %s: %v", wgCfg.Name, peer.AllowedIPs, err)
				continue
			}
			if err := ns.AddPeerRoute(wgCfg.Name, peerPrefix, netip.Addr{}); err != nil {
				log.Printf("%s: add peer route %s: %v", wgCfg.Name, peerPrefix, err)
			}
		}

		if err := t.Up(); err != nil {
			log.Fatalf("%s up: %v", wgCfg.Name, err)
		}
		r.AddTransport(t)
		go handleOutbound(ctx, ns, wgCfg.Name, t)
		log.Printf("wg %s: %s :%d peers=%d", wgCfg.Name, wgCfg.Address, wgCfg.ListenPort, len(wgCfg.Peers))
	}

	// BGP speaker with proxy
	if cfg.BGP.ASN > 0 {
		var bgpPeers []bgp.PeerConfig
		for _, p := range cfg.BGP.Peers {
			bgpPeers = append(bgpPeers, bgp.PeerConfig{
				Name:        p.Name,
				Address:     p.Address,
				ASN:         p.ASN,
				PeerBGPPort: p.PeerBGPPort,
				Families:    p.Families,
			})
		}

		var localRoutes []bgp.LocalRoute
		for _, lr := range cfg.BGP.LocalRoutes {
			pfx, _ := netip.ParsePrefix(lr.Prefix)
			nh, _ := netip.ParseAddr(lr.NextHop)
			localRoutes = append(localRoutes, bgp.LocalRoute{
				Prefix:  pfx,
				NextHop: nh,
				Label:   lr.Label,
			})
		}

		speaker := bgp.NewSpeaker(bgp.SpeakerConfig{
			ASN:          cfg.BGP.ASN,
			RouterID:     cfg.BGP.RouterID,
			ImportFilter: cfg.BGP.ImportFilter,
			Peers:        bgpPeers,
			LocalRoutes:  localRoutes,
		}, fib, lfib, ns)
		if err := speaker.Start(ctx); err != nil {
			log.Fatalf("bgp: %v", err)
		}
		defer speaker.Stop()
	}

	// Local TCP listener via netstack
	if cfg.Netstack.TCPPort > 0 {
		listener, err := ns.ListenTCP(uint16(cfg.Netstack.TCPPort))
		if err != nil {
			log.Printf("listen tcp: %v", err)
		} else {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hello World"))
			})
			go func() {
				log.Printf("http server on netstack :%d", cfg.Netstack.TCPPort)
				if err := http.Serve(listener, mux); err != nil {
					if ctx.Err() == nil {
						log.Printf("http: %v", err)
					}
				}
			}()
		}
	}

	log.Printf("gouter started: %d wg + %v mpls transports",
		len(cfg.WireGuard), cfg.MPLS != nil)

	go func() {
		verbose := os.Getenv("GOUTER_VERBOSE") != ""
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				routes := fib.List()
				if verbose {
					log.Printf("fib: %d routes:", len(routes))
					for _, r := range routes {
						log.Printf("  %s via %s [%s]", r.Prefix, r.NextHop, r.Transport)
					}
				} else {
					log.Printf("fib: %d routes", len(routes))
				}
			}
		}
	}()

	r.Run(ctx)
	log.Printf("shutting down...")
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
			if err := t.Write(pkt); err != nil {
				log.Printf("outbound %s: %v", name, err)
			}
		}
	}
}
