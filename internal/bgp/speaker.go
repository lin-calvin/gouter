package bgp

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"gouter/internal/mpls"
	"gouter/internal/netstack"
	"gouter/internal/router"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

type PeerConfig struct {
	Name        string
	Address     string   // peer's WG IP (e.g. 10.0.1.2)
	ASN         uint32
	PeerBGPPort uint16   // peer's BGP listen port (default 179)
	Families    []string // e.g. ["ipv4-unicast", "ipv4-labelled-unicast"]
}

type LocalRoute struct {
	Prefix  netip.Prefix
	NextHop netip.Addr
	Label   bool
}

type SpeakerConfig struct {
	ASN          uint32
	RouterID     string
	ImportFilter []string
	Peers        []PeerConfig
	LocalRoutes  []LocalRoute
}

type Speaker struct {
	cfg        SpeakerConfig
	server     *server.BgpServer
	fib        *router.FIB
	lfib       *mpls.LFIB
	proxyMgr   *ProxyManager
	routeCount int
}

const gobgpInternalPort = 1790

func NewSpeaker(cfg SpeakerConfig, fib *router.FIB, lfib *mpls.LFIB, ns *netstack.Manager) *Speaker {
	levelVar := new(slog.LevelVar)
	if os.Getenv("GOUTER_BGP_DEBUG") != "" {
		levelVar.Set(slog.LevelDebug)
	} else {
		levelVar.Set(slog.LevelInfo)
	}
	bgpLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: levelVar}))
	return &Speaker{
		cfg:      cfg,
		server:   server.NewBgpServer(server.LoggerOption(bgpLogger, levelVar)),
		fib:      fib,
		lfib:     lfib,
		proxyMgr: NewProxyManager(ns, gobgpInternalPort, netip.Addr{}, 0),
	}
}

func (s *Speaker) Start(ctx context.Context) error {
	go s.server.Serve()

	if err := s.server.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        s.cfg.ASN,
			RouterId:   s.cfg.RouterID,
			ListenPort: gobgpInternalPort,
		},
	}); err != nil {
		return fmt.Errorf("start bgp: %w", err)
	}

	if err := setupFilter(ctx, s.server, s.cfg.ImportFilter); err != nil {
		log.Printf("bgp: filter setup: %v", err)
	}

	if err := s.setupGlobalNexthop(ctx); err != nil {
		log.Printf("bgp: global nexthop: %v", err)
	}

	for _, p := range s.cfg.Peers {
		if err := s.addPeer(ctx, p); err != nil {
			return fmt.Errorf("add peer %s: %w", p.Name, err)
		}
	}

	if err := s.proxyMgr.StartInbound(ctx); err != nil {
		return fmt.Errorf("start inbound proxy: %w", err)
	}

	for _, r := range s.cfg.LocalRoutes {
		if err := s.addLocalRoute(r); err != nil {
			log.Printf("bgp: add local route %s: %v", r.Prefix, err)
		}
	}

	if err := s.server.WatchEvent(ctx, server.WatchEventMessageCallbacks{
		OnBestPath: s.handleBestPath,
	}, server.WatchBestPath(true)); err != nil {
		return fmt.Errorf("watch event: %w", err)
	}

	log.Printf("bgp: AS%d %s (gobgp:1790, netstack:179), %d peers", s.cfg.ASN, s.cfg.RouterID, len(s.cfg.Peers))
	return nil
}

func (s *Speaker) Stop() {
	s.proxyMgr.Close()
	s.server.StopBgp(context.Background(), &api.StopBgpRequest{})
}

func (s *Speaker) addPeer(ctx context.Context, p PeerConfig) error {
	peerAddr, err := netip.ParseAddr(p.Address)
	if err != nil {
		return fmt.Errorf("bad peer address %s: %w", p.Address, err)
	}

	peerBgpPort := p.PeerBGPPort
	if peerBgpPort == 0 {
		peerBgpPort = 179
	}
	proxy, err := s.proxyMgr.CreateProxy(p.Name, peerAddr, peerBgpPort)
	if err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}

	afiSafis := buildAfiSafis(p.Families)

	log.Printf("bgp: peer %s: %s AS%d → gobgp neighbor %s:%d, families=%v",
		p.Name, p.Address, p.ASN, proxy.LocalIP, proxy.OutboundPort, p.Families)

	if err := s.server.AddPeer(ctx, &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: proxy.LocalIP.String(),
				PeerAsn:         p.ASN,
				LocalAsn:        s.cfg.ASN,
			},
			Transport: &api.Transport{
				RemotePort: uint32(proxy.OutboundPort),
			},
			Timers: &api.Timers{
				Config: &api.TimersConfig{
					ConnectRetry: 10,
				},
			},
			AfiSafis: afiSafis,
			GracefulRestart: &api.GracefulRestart{
				Enabled:     true,
				RestartTime: 120,
			},
		},
	}); err != nil {
		return fmt.Errorf("add peer: %w", err)
	}

	return nil
}

func (s *Speaker) setupGlobalNexthop(ctx context.Context) error {
	name := "nexthop-override"
	s.server.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
		Name: name,
		Statements: []*api.Statement{{
			Name:    "set-nh",
			Actions: &api.Actions{Nexthop: &api.NexthopAction{Address: s.cfg.RouterID}},
		}},
	}})
	return s.server.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name:          "global",
		Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
		Policies:      []*api.Policy{{Name: name}},
		DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
	}})
}

func (s *Speaker) addLocalRoute(r LocalRoute) error {
	var family bgp.Family
	var nlri bgp.NLRI
	var err error

	if r.Label {
		family = bgp.RF_IPv4_MPLS
		label := s.lfib.Allocate()
		nlri, err = bgp.NewLabeledIPAddrPrefix(r.Prefix, *bgp.NewMPLSLabelStack(label))
		routerID, _ := netip.ParseAddr(s.cfg.RouterID)
		s.lfib.Add(mpls.LFIBEntry{
			InLabel: label,
			Op:      mpls.OpPop,
			NextHop: routerID,
		})
		log.Printf("bgp-lu: local label %d → pop → %s", label, r.Prefix)
	} else {
		family = bgp.RF_IPv4_UC
		nlri, err = bgp.NewIPAddrPrefix(r.Prefix)
	}
	if err != nil {
		return err
	}

	nh, err := bgp.NewPathAttributeNextHop(r.NextHop)
	if err != nil {
		return err
	}
	origin := bgp.NewPathAttributeOrigin(0)

	p := &apiutil.Path{
		Family: family,
		Nlri:   nlri,
		Attrs:  []bgp.PathAttributeInterface{origin, nh},
	}

	_, err = s.server.AddPath(apiutil.AddPathRequest{
		Paths: []*apiutil.Path{p},
	})
	return err
}

func (s *Speaker) handleBestPath(paths []*apiutil.Path, t time.Time) {
	_ = t
	for _, p := range paths {
		switch p.Family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			s.handleUnicastPath(p)
		case bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS:
			s.handleLabeledPath(p)
		case bgp.RF_SR_POLICY_IPv4, bgp.RF_SR_POLICY_IPv6:
			s.handleSRPolicy(p)
		}
	}
}

func (s *Speaker) handleUnicastPath(p *apiutil.Path) {
	prefix, nextHop, ok := extractUnicastInfo(p)
	if !ok {
		return
	}
	if p.Withdrawal {
		s.fib.Remove(prefix)
		log.Printf("bgp: withdraw %s", prefix)
	} else {
		s.fib.Add(router.FIBEntry{
			Prefix:    prefix,
			NextHop:   nextHop,
			Action:    router.ActionForward,
			Transport: "",
		})
		s.routeCount++
		if os.Getenv("GOUTER_VERBOSE_ROUTE") != "" || s.routeCount <= 10 || s.routeCount%500 == 0 {
			log.Printf("bgp: %s via %s (%d routes)", prefix, nextHop, len(s.fib.List()))
		}
	}
}

func (s *Speaker) handleLabeledPath(p *apiutil.Path) {
	prefix, nextHop, labels, ok := extractLabeledInfo(p)
	if !ok || len(labels) == 0 {
		return
	}
	label := labels[0]

	if p.Withdrawal {
		s.fib.Remove(prefix)
		log.Printf("bgp-lu: withdraw %s label=%d", prefix, label)
		return
	}

	routerID := netip.MustParseAddr(s.cfg.RouterID)
	if nextHop == routerID {
		s.lfib.Add(mpls.LFIBEntry{
			InLabel: label,
			Op:      mpls.OpPop,
			NextHop: nextHop,
		})
		log.Printf("bgp-lu: local label %d → pop → %s", label, prefix)
	} else {
		s.fib.Add(router.FIBEntry{
			Prefix:    prefix,
			NextHop:   nextHop,
			Action:    router.ActionPush,
			OutLabels: labels,
			Transport: "",
		})
		log.Printf("bgp-lu: learned %s via %s label=%d", prefix, nextHop, label)
	}
}

func (s *Speaker) handleSRPolicy(p *apiutil.Path) {
	nlri, ok := p.Nlri.(*bgp.SRPolicyNLRI)
	if !ok {
		return
	}
	var endp netip.Addr
	switch nlri.Endpoint {
	default:
		if len(nlri.Endpoint) >= 4 {
			endp, _ = netip.AddrFromSlice(nlri.Endpoint[:4])
		}
	}
	if !endp.IsValid() {
		return
	}
	endpointPrefix := netip.PrefixFrom(endp, 32)

	segments := extractSegments(p.Attrs)

	if p.Withdrawal {
		s.fib.Remove(endpointPrefix)
		log.Printf("bgp-sr: withdraw color=%d endpoint=%s", nlri.Color, endp)
	} else {
		s.fib.Add(router.FIBEntry{
			Prefix:    endpointPrefix,
			NextHop:   endp,
			Action:    router.ActionPush,
			OutLabels: segments,
			Transport: "",
		})
		log.Printf("bgp-sr: color=%d endpoint=%s segments=%v", nlri.Color, endp, segments)
	}
}

func extractSegments(attrs []bgp.PathAttributeInterface) []uint32 {
	for _, attr := range attrs {
		encap, ok := attr.(*bgp.PathAttributeTunnelEncap)
		if !ok {
			continue
		}
		for _, tlv := range encap.Value {
			for _, sub := range tlv.Value {
				if sl, ok := sub.(*bgp.TunnelEncapSubTLVSRSegmentList); ok {
					var labels []uint32
					for _, seg := range sl.Segments {
						if typeA, ok := seg.(*bgp.SegmentTypeA); ok {
							labels = append(labels, typeA.Label>>12)
						}
					}
					return labels
				}
			}
		}
	}
	return nil
}

func buildAfiSafis(families []string) []*api.AfiSafi {
	var result []*api.AfiSafi
	for _, f := range families {
		fam := familyFromString(f)
		if fam == nil {
			continue
		}
		result = append(result, &api.AfiSafi{
			Config: &api.AfiSafiConfig{
				Family:  fam,
				Enabled: true,
			},
		})
	}
	if len(result) == 0 {
		result = append(result, &api.AfiSafi{
			Config: &api.AfiSafiConfig{
				Family:  &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
				Enabled: true,
			},
		})
	}
	return result
}

func familyFromString(s string) *api.Family {
	switch s {
	case "ipv4-unicast":
		return &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}
	case "ipv6-unicast":
		return &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}
	case "ipv4-labelled-unicast":
		return &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_MPLS_LABEL}
	case "ipv6-labelled-unicast":
		return &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_MPLS_LABEL}
	case "ipv4-srpolicy":
		return &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_SR_POLICY}
	default:
		return nil
	}
}

func extractUnicastInfo(p *apiutil.Path) (prefix netip.Prefix, nextHop netip.Addr, ok bool) {
	switch nlri := p.Nlri.(type) {
	case *bgp.IPAddrPrefix:
		prefix = nlri.Prefix
	default:
		return netip.Prefix{}, netip.Addr{}, false
	}
	nextHop = extractNextHop(p.Attrs)
	if !nextHop.IsValid() {
		return netip.Prefix{}, netip.Addr{}, false
	}
	return prefix, nextHop, true
}

func extractLabeledInfo(p *apiutil.Path) (prefix netip.Prefix, nextHop netip.Addr, labels []uint32, ok bool) {
	switch nlri := p.Nlri.(type) {
	case *bgp.LabeledIPAddrPrefix:
		prefix = nlri.Prefix
		labels = nlri.Labels.Labels
	case *bgp.LabeledVPNIPAddrPrefix:
		prefix = nlri.Prefix
		labels = nlri.Labels.Labels
	default:
		return netip.Prefix{}, netip.Addr{}, nil, false
	}
	nextHop = extractNextHop(p.Attrs)
	if !nextHop.IsValid() {
		return netip.Prefix{}, netip.Addr{}, nil, false
	}
	return prefix, nextHop, labels, true
}

func extractNextHop(attrs []bgp.PathAttributeInterface) netip.Addr {
	for _, attr := range attrs {
		if nh, ok := attr.(*bgp.PathAttributeNextHop); ok {
			return nh.Value
		}
		if nh, ok := attr.(*bgp.PathAttributeMpReachNLRI); ok {
			return nh.Nexthop
		}
	}
	return netip.Addr{}
}
