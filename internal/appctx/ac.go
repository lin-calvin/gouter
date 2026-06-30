package appctx

import (
	"gouter/internal/bgp"
	"gouter/internal/config"
	"gouter/internal/mpls"
	"gouter/internal/netstack"
	"gouter/internal/router"
)

type AppContext struct {
	Config     *config.Config
	NS         *netstack.Manager
	FIB        *router.FIB
	Nexthop    *router.NexthopResolver
	LFIB       *mpls.LFIB
	Router     *router.Router
	BGPSpeaker *bgp.Speaker
}

func New(cfg *config.Config) *AppContext {
	ac := &AppContext{Config: cfg}
	ac.NS = netstack.NewManager(cfg.IPv6Enabled())
	ac.FIB = router.NewFIB()
	ac.Nexthop = router.NewNexthopResolver(ac.FIB)
	ac.LFIB = mpls.NewLFIB()
	ac.Router = router.NewRouter(ac.FIB, ac.Nexthop, ac.NS, ac.LFIB)
	return ac
}

func (ac *AppContext) GetFIB() *router.FIB           { return ac.FIB }
func (ac *AppContext) GetLFIB() *mpls.LFIB           { return ac.LFIB }
func (ac *AppContext) GetNS() *netstack.Manager      { return ac.NS }
