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

		var exportRoutes []config.RouteConfig
		for _, r := range cfg.Routes {
			applyRoute(r, fib, lfib)
			if r.Export {
				exportRoutes = append(exportRoutes, r)
			}
		}

		speaker := bgp.NewSpeaker(bgp.SpeakerConfig{
			ASN:          cfg.BGP.ASN,
			RouterID:     cfg.BGP.RouterID,
			ImportFilter: cfg.BGP.ImportFilter,
			Peers:        bgpPeers,
			ExportRoutes: exportRoutes,
			LSLinks:      lsLinks,
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

	log.Printf("gouter started: %d links + %d legacy wg + %v mpls transports",
		len(cfg.Links), len(cfg.WireGuard), cfg.MPLS != nil)

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
		log.Printf("using links[] config format (%d links)", len(cfg.Links))

		// Collect unique addresses, create one NIC per address
		nics := make(map[string]string) // address → NIC name
		for _, link := range cfg.Links {
			if link.Address != "" {
				if _, ok := nics[link.Address]; !ok {
					nicName := "nic-" + link.Address
					addrPrefix, err := netip.ParsePrefix(link.Address)
					if err != nil {
						log.Fatalf("bad link address %s: %v", link.Address, err)
					}
					_, err = ns.AddNIC(netstack.NICConfig{Name: nicName, Address: addrPrefix, MTU: 1500})
					if err != nil {
						log.Fatalf("add nic %s: %v", nicName, err)
				}
				nics[link.Address] = nicName
				ns.AddDefaultRoute(nicName)
				go handleOutbound(ctx, ns, nicName, r)
				log.Printf("nic %s: %s", nicName, link.Address)
				}
			}
		}

		for _, link := range cfg.Links {
			setupLinkTransport(ctx, cfg, ns, nexthop, r, link, nics[link.Address])
		}
		return
	}
	log.Printf("using legacy wireguard[] config format")
	for _, wgCfg := range cfg.WireGuard {
		setupOldWG(ctx, cfg, ns, nexthop, r, wgCfg)
	}
	if cfg.MPLS != nil && cfg.MPLS.UDP.ListenPort > 0 {
		setupOldMPLS(ctx, cfg, ns, nexthop, r, cfg.MPLS)
	}
}

func setupLinkTransport(ctx context.Context, cfg *config.Config, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, link config.LinkConfig, nicName string) {
	switch {
	case link.WG != nil:
		setupLinkWG(ctx, ns, nexthop, r, link, link.WG, nicName)
	case link.MPLSUDP != nil:
		setupLinkMPLS(ctx, ns, nexthop, r, link, link.MPLSUDP, nicName)
	}
}

func setupLinkWG(ctx context.Context, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, link config.LinkConfig, wgCfg *config.WGLinkConfig, nicName string) {
	t := wg.NewTransport(link.Name, wgCfg.MTU, device.LogLevelError)
	skHex, err := config.B64ToHex(wgCfg.PrivateKey)
	if err != nil {
		log.Fatalf("%s: bad private key: %v", link.Name, err)
	}
	pkHex, err := config.B64ToHex(wgCfg.PublicKey)
	if err != nil {
		log.Fatalf("%s: bad public key: %v", link.Name, err)
	}
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n",
		skHex, wgCfg.ListenPort, pkHex, wgCfg.AllowedIPs)
	if wgCfg.Endpoint != "" {
		uapi += fmt.Sprintf("endpoint=%s\n", wgCfg.Endpoint)
	}
	if wgCfg.PersistentKeepalive > 0 {
		uapi += fmt.Sprintf("persistent_keepalive_interval=%d\n", wgCfg.PersistentKeepalive)
	}
	if err := t.Configure(uapi); err != nil {
		log.Fatalf("%s: configure: %v", link.Name, err)
	}

	// NexthopResolver: transport → peer IPs
	var prefixes []netip.Prefix
	if link.Address != "" {
		if pfx, err := netip.ParsePrefix(link.Address); err == nil {
			prefixes = append(prefixes, pfx)
		}
	}
	if allowed, err := netip.ParsePrefix(wgCfg.AllowedIPs); err == nil {
		prefixes = append(prefixes, allowed)
	}
	if link.PeerIP != "" {
		if peerIP, err := netip.ParseAddr(link.PeerIP); err == nil {
			peerPrefix := netip.PrefixFrom(peerIP, 32)
			prefixes = append(prefixes, peerPrefix)
			r.FIB().Add(router.FIBEntry{
				Prefix:    peerPrefix,
				NextHop:   peerIP,
				Action:    router.ActionForward,
				Transport: link.Name,
			})
			if nicName != "" {
				ns.AddPeerRoute(nicName, peerPrefix, netip.Addr{})
			}
		}
	}
	nexthop.AddTransport(link.Name, prefixes)

	if err := t.Up(); err != nil {
		log.Fatalf("%s up: %v", link.Name, err)
	}
	r.AddTransport(t)
	log.Printf("wg %s: %s :%d", link.Name, link.Address, wgCfg.ListenPort)
}

func setupLinkMPLS(ctx context.Context, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, link config.LinkConfig, mp *config.MPLSUDPLink, nicName string) {
	mplsAddr := netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), uint16(mp.ListenPort))
	mplsT, _ := mpls.NewUDPTransport(link.Name, mplsAddr)
	var prefixes []netip.Prefix
	for _, peer := range mp.Peers {
		if pa, err := netip.ParseAddrPort(peer); err == nil {
			mplsT.AddPeer(pa.Addr(), pa)
			prefixes = append(prefixes, netip.PrefixFrom(pa.Addr(), 32))
		}
	}
	nexthop.AddTransport(link.Name, prefixes)
	r.AddTransport(mplsT)
	log.Printf("mpls/udp %s: :%d peers=%d", link.Name, mp.ListenPort, len(mp.Peers))
}

func setupOldWG(ctx context.Context, cfg *config.Config, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, wgCfg config.WireGuardConf) {
	t := wg.NewTransport(wgCfg.Name, wgCfg.MTU, device.LogLevelError)
	skHex, err := config.B64ToHex(wgCfg.PrivateKey)
	if err != nil {
		log.Fatalf("%s: bad private key: %v", wgCfg.Name, err)
	}
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\n", skHex, wgCfg.ListenPort)
	for _, p := range wgCfg.Peers {
		pkHex, err := config.B64ToHex(p.PublicKey)
		if err != nil {
			log.Fatalf("%s: bad peer public key: %v", wgCfg.Name, err)
		}
		uapi += fmt.Sprintf("public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n", pkHex, p.Endpoint, p.AllowedIPs)
	}
	if err := t.Configure(uapi); err != nil {
		log.Fatalf("%s: configure: %v", wgCfg.Name, err)
	}
	addrPrefix, _ := netip.ParsePrefix(wgCfg.Address)
	ns.AddNIC(netstack.NICConfig{Name: wgCfg.Name, Address: addrPrefix, MTU: 1500})
	prefixes := []netip.Prefix{addrPrefix}
	for _, p := range wgCfg.Peers {
		if allowed, err := netip.ParsePrefix(p.AllowedIPs); err == nil {
			prefixes = append(prefixes, allowed)
		}
	}
	nexthop.AddTransport(wgCfg.Name, prefixes)
	t.Up()
	r.AddTransport(t)
	go handleOutbound(ctx, ns, wgCfg.Name, r)
	log.Printf("wg %s: %s :%d", wgCfg.Name, wgCfg.Address, wgCfg.ListenPort)
}

func setupOldMPLS(ctx context.Context, cfg *config.Config, ns *netstack.Manager, nexthop *router.NexthopResolver, r *router.Router, mp *config.MPLSConfig) {
	mplsAddr := netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), uint16(mp.UDP.ListenPort))
	mplsT, _ := mpls.NewUDPTransport("mpls-udp", mplsAddr)
	mplsNIC := netip.MustParsePrefix("10.255.255.1/32")
	ns.AddNIC(netstack.NICConfig{Name: "mpls-udp", Address: mplsNIC, MTU: 1500})
	prefixes := []netip.Prefix{mplsNIC}
	for _, peer := range mp.UDP.Peers {
		if pa, err := netip.ParseAddrPort(peer); err == nil {
			mplsT.AddPeer(pa.Addr(), pa)
			prefixes = append(prefixes, netip.PrefixFrom(pa.Addr(), 32))
		}
	}
	nexthop.AddTransport("mpls-udp", prefixes)
	r.AddTransport(mplsT)
	go handleOutbound(ctx, ns, "mpls-udp", r)
	log.Printf("mpls/udp: :%d peers=%d", mp.UDP.ListenPort, len(mp.UDP.Peers))
}

func collectLSFromLinks(cfg *config.Config) []bgp.LSLinkInfo {
	var result []bgp.LSLinkInfo
	for _, link := range cfg.Links {
		if link.LS == nil || link.WG == nil {
			continue
		}
		localAddr, _ := netip.ParsePrefix(link.Address)
		peerAddr, _ := netip.ParseAddr(link.PeerIP)
		result = append(result, bgp.LSLinkInfo{
			LocalAddr:      localAddr.Addr(),
			PeerAddr:       peerAddr,
			RemoteRouterID: link.LS.RemoteRouterID,
			RemoteASN:      link.LS.RemoteASN,
			Metric:         link.LS.Metric,
			AdjSID:         link.LS.AdjSID,
		})
	}
	return result
}

func applyRoute(route config.RouteConfig, fib *router.FIB, lfib *mpls.LFIB) {
	prefix, err := netip.ParsePrefix(route.Prefix)
	if err != nil {
		log.Printf("route: bad prefix %s: %v", route.Prefix, err)
		return
	}
	nh, err := netip.ParseAddr(route.NextHop)
	if err != nil {
		log.Printf("route: bad nexthop %s: %v", route.NextHop, err)
		return
	}
	nhForFIB := nh
	if !nh.IsValid() {
		nhForFIB = netip.Addr{}
	}

	transport := route.Via
	switch {
	case route.InLabel > 0 && len(route.Labels) > 0:
		lfib.Add(mpls.LFIBEntry{
			InLabel:   route.InLabel,
			Op:        mpls.OpSwap,
			OutLabels: route.Labels,
			NextHop:   nhForFIB,
			Transport: transport,
		})
		log.Printf("route: LFIB %d→SWAP%v via %s (%s)", route.InLabel, route.Labels, nh, route.Prefix)

	case route.InLabel > 0:
		lfib.Add(mpls.LFIBEntry{
			InLabel:   route.InLabel,
			Op:        mpls.OpPop,
			NextHop:   nhForFIB,
			Transport: transport,
		})
		log.Printf("route: LFIB %d→POP (%s)", route.InLabel, route.Prefix)

	case len(route.Labels) > 0:
		if existing := fib.HasExact(prefix); existing != nil && existing.Transport != "" {
			log.Printf("route: CONFLICT %s already in FIB via %s — remove from routes config and use link's peer_ip instead",
				route.Prefix, existing.Transport)
			return
		}
		fib.Add(router.FIBEntry{
			Prefix:    prefix,
			NextHop:   nhForFIB,
			Action:    router.ActionPush,
			OutLabels: route.Labels,
			Transport: transport,
		})
		log.Printf("route: FIB %s PUSH%v via %s", route.Prefix, route.Labels, nh)

	default:
		if existing := fib.HasExact(prefix); existing != nil && existing.Transport != "" {
			log.Printf("route: CONFLICT %s already in FIB via %s — remove from routes config and use link's peer_ip instead",
				route.Prefix, existing.Transport)
			return
		}
		fib.Add(router.FIBEntry{
			Prefix:    prefix,
			NextHop:   nhForFIB,
			Action:    router.ActionForward,
			Transport: transport,
		})
		log.Printf("route: FIB %s via %s", route.Prefix, nh)
	}
}

func handleOutbound(ctx context.Context, ns *netstack.Manager, name string, r *router.Router) {
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
			r.ForwardFromNetstack(pkt)
		}
	}
}
