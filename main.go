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

	setupTransports(ctx, cfg, ns, nexthop, r)

	var lsLinks []bgp.LSLinkInfo
	if len(cfg.Links) > 0 {
		lsLinks = collectLSFromLinks(cfg)
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
			LSLinks:      lsLinks,
		}, fib, lfib, ns)
		if err := speaker.Start(ctx); err != nil {
			log.Fatalf("bgp: %v", err)
		}
		defer speaker.Stop()

		// Apply static SR policies from config
		for _, sp := range cfg.BGP.SRPolicies {
			endp, err := netip.ParseAddr(sp.Endpoint)
			if err != nil {
				log.Printf("sr-policy: bad endpoint %s: %v", sp.Endpoint, err)
				continue
			}
			fib.Add(router.FIBEntry{
				Prefix:    netip.PrefixFrom(endp, 32),
				NextHop:   endp,
				Action:    router.ActionPush,
				OutLabels: sp.Segments,
				Transport: "",
			})
			log.Printf("sr-policy: endpoint=%s color=%d segments=%v", sp.Endpoint, sp.Color, sp.Segments)
		}
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

func setupTransports(ctx context.Context, cfg *config.Config, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router) {
	if len(cfg.Links) > 0 {
		for _, link := range cfg.Links {
			setupLinkTransport(ctx, cfg, ns, nexthop, r, link)
		}
		return
	}
	for _, wgCfg := range cfg.WireGuard {
		setupOldWG(ctx, cfg, ns, nexthop, r, wgCfg)
	}
	if cfg.MPLS != nil && cfg.MPLS.UDP.ListenPort > 0 {
		setupOldMPLS(ctx, cfg, ns, nexthop, r, cfg.MPLS)
	}
}

func setupLinkTransport(ctx context.Context, cfg *config.Config, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, link config.LinkConfig) {
	switch {
	case link.WG != nil:
		setupLinkWG(ctx, ns, nexthop, r, link.Name, link.WG)
	case link.MPLSUDP != nil:
		setupLinkMPLS(ctx, ns, nexthop, r, link.Name, link.MPLSUDP)
	}
}

func setupLinkWG(ctx context.Context, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, name string, wgCfg *config.WGLinkConfig) {
	t := wg.NewTransport(name, wgCfg.MTU, device.LogLevelError)
	skHex, _ := config.B64ToHex(wgCfg.PrivateKey)
	pkHex, _ := config.B64ToHex(wgCfg.PublicKey)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\npublic_key=%s\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n",
		skHex, wgCfg.ListenPort, pkHex, wgCfg.Endpoint, wgCfg.AllowedIPs)
	if err := t.Configure(uapi); err != nil {
		log.Printf("%s: configure: %v", name, err)
	}
	addrPrefix, _ := netip.ParsePrefix(wgCfg.Address)
	ns.AddNIC(netstack.NICConfig{Name: name, Address: addrPrefix, MTU: 1500})
	nexthop.AddTransport(name, []netip.Prefix{addrPrefix})
	if allowed, err := netip.ParsePrefix(wgCfg.AllowedIPs); err == nil {
		ns.AddPeerRoute(name, allowed, netip.Addr{})
	}
	t.Up()
	r.AddTransport(t)
	go handleOutbound(ctx, ns, name, t)
	log.Printf("wg %s: %s :%d", name, wgCfg.Address, wgCfg.ListenPort)
}

func setupLinkMPLS(ctx context.Context, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, name string, mp *config.MPLSUDPLink) {
	mplsAddr := netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), uint16(mp.ListenPort))
	mplsT, _ := mpls.NewUDPTransport(name, mplsAddr)
	for _, peer := range mp.Peers {
		if pa, err := netip.ParseAddrPort(peer); err == nil {
			mplsT.AddPeer(pa.Addr(), pa)
		}
	}
	mplsNIC := netip.MustParsePrefix("10.255.255.1/32")
	ns.AddNIC(netstack.NICConfig{Name: name, Address: mplsNIC, MTU: 1500})
	nexthop.AddTransport(name, []netip.Prefix{mplsNIC})
	r.AddTransport(mplsT)
	go handleOutbound(ctx, ns, name, mplsT)
	log.Printf("mpls/udp %s: :%d peers=%d", name, mp.ListenPort, len(mp.Peers))
}

func setupOldWG(ctx context.Context, cfg *config.Config, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, wgCfg config.WireGuardConf) {
	t := wg.NewTransport(wgCfg.Name, wgCfg.MTU, device.LogLevelError)
	skHex, _ := config.B64ToHex(wgCfg.PrivateKey)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\n", skHex, wgCfg.ListenPort)
	for _, p := range wgCfg.Peers {
		pkHex, _ := config.B64ToHex(p.PublicKey)
		uapi += fmt.Sprintf("public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n", pkHex, p.Endpoint, p.AllowedIPs)
	}
	t.Configure(uapi)
	addrPrefix, _ := netip.ParsePrefix(wgCfg.Address)
	ns.AddNIC(netstack.NICConfig{Name: wgCfg.Name, Address: addrPrefix, MTU: 1500})
	nexthop.AddTransport(wgCfg.Name, []netip.Prefix{addrPrefix})
	for _, p := range wgCfg.Peers {
		if allowed, err := netip.ParsePrefix(p.AllowedIPs); err == nil {
			ns.AddPeerRoute(wgCfg.Name, allowed, netip.Addr{})
		}
	}
	t.Up()
	r.AddTransport(t)
	go handleOutbound(ctx, ns, wgCfg.Name, t)
	log.Printf("wg %s: %s :%d", wgCfg.Name, wgCfg.Address, wgCfg.ListenPort)
}

func setupOldMPLS(ctx context.Context, cfg *config.Config, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, mp *config.MPLSConfig) {
	mplsAddr := netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), uint16(mp.UDP.ListenPort))
	mplsT, _ := mpls.NewUDPTransport("mpls-udp", mplsAddr)
	for _, peer := range mp.UDP.Peers {
		if pa, err := netip.ParseAddrPort(peer); err == nil {
			mplsT.AddPeer(pa.Addr(), pa)
		}
	}
	mplsNIC := netip.MustParsePrefix("10.255.255.1/32")
	ns.AddNIC(netstack.NICConfig{Name: "mpls-udp", Address: mplsNIC, MTU: 1500})
	nexthop.AddTransport("mpls-udp", []netip.Prefix{mplsNIC})
	r.AddTransport(mplsT)
	go handleOutbound(ctx, ns, "mpls-udp", mplsT)
	log.Printf("mpls/udp: :%d peers=%d", mp.UDP.ListenPort, len(mp.UDP.Peers))
}

func collectLSFromLinks(cfg *config.Config) []bgp.LSLinkInfo {
	var result []bgp.LSLinkInfo
	for _, link := range cfg.Links {
		if link.LS == nil || link.WG == nil {
			continue
		}
		localAddr, _ := netip.ParsePrefix(link.WG.Address)
		peerAddr, _ := netip.ParsePrefix(link.WG.AllowedIPs)
		result = append(result, bgp.LSLinkInfo{
			LocalAddr:      localAddr.Addr(),
			PeerAddr:       peerAddr.Addr(),
			RemoteRouterID: link.LS.RemoteRouterID,
			RemoteASN:      link.LS.RemoteASN,
			Metric:         link.LS.Metric,
			AdjSID:         link.LS.AdjSID,
		})
	}
	return result
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
