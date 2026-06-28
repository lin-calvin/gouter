package router

import (
	"context"
	"log"
	"net/netip"
	"sync"

	"gouter/internal/mpls"
	"gouter/internal/netstack"
	"gouter/internal/transport"
)

type Router struct {
	transports map[string]transport.Transport
	fib        *FIB
	nexthop    *NexthopResolver
	netstack   *netstack.Manager
	lfib       *mpls.LFIB
	processor  PacketProcessor
	isLocal    func(netip.Addr) bool
	nicForAddr func(netip.Addr) (string, bool)

	mu sync.RWMutex
}

type PacketProcessor interface {
	Process(pkt []byte) []byte
}

type NullProcessor struct{}

func (NullProcessor) Process(pkt []byte) []byte { return pkt }

func NewRouter(fib *FIB, nexthop *NexthopResolver, ns *netstack.Manager, lfib *mpls.LFIB) *Router {
	return &Router{
		transports: make(map[string]transport.Transport),
		fib:        fib,
		nexthop:    nexthop,
		netstack:   ns,
		lfib:       lfib,
		processor:  NullProcessor{},
		isLocal:    ns.IsLocalAddress,
		nicForAddr: ns.NICNameForAddress,
	}
}

func (r *Router) AddTransport(t transport.Transport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transports[t.Name()] = t
}

func (r *Router) RemoveTransport(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.transports, name)
}

func (r *Router) SetProcessor(p PacketProcessor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.processor = p
}

func (r *Router) ForwardFromNetstack(pkt transport.Packet) {
	r.handlePacket(pkt)
}

func (r *Router) LFIB() *mpls.LFIB {
	return r.lfib
}

func (r *Router) FIB() *FIB {
	return r.fib
}

func (r *Router) Run(ctx context.Context) {
	r.mu.RLock()
	names := make([]string, 0, len(r.transports))
	for name := range r.transports {
		names = append(names, name)
	}
	r.mu.RUnlock()

	for _, name := range names {
		go r.runTransportReader(ctx, name)
	}

	<-ctx.Done()
}

func (r *Router) runTransportReader(ctx context.Context, name string) {
	r.mu.RLock()
	t, ok := r.transports[name]
	r.mu.RUnlock()
	if !ok {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-t.Read():
			if !ok {
				return
			}
			r.handlePacket(pkt)
		}
	}
}

func (r *Router) handlePacket(pkt transport.Packet) {
	r.mu.RLock()
	proc := r.processor
	r.mu.RUnlock()
	processed := proc.Process(pkt.Data)
	if processed == nil {
		return
	}
	pkt.Data = processed

	switch pkt.Type {
	case transport.PacketIP:
		r.handleIPPacket(pkt)
	case transport.PacketMPLS:
		r.handleMPLSPacket(pkt)
	}
}

func (r *Router) handleIPPacket(pkt transport.Packet) {
	if len(pkt.Data) < 20 {
		return
	}

	var dstIP netip.Addr
	ttlIdx := -1
	version := pkt.Data[0] >> 4
	switch version {
	case 4:
		if len(pkt.Data) < 20 {
			return
		}
		dstIP, _ = netip.AddrFromSlice(pkt.Data[16:20])
		ttlIdx = 8
	case 6:
		if len(pkt.Data) < 40 {
			return
		}
		dstIP, _ = netip.AddrFromSlice(pkt.Data[24:40])
		ttlIdx = 7
	default:
		return
	}

	if r.isLocal(dstIP) {
		if nicName, ok := r.nicForAddr(dstIP); ok {
			if err := r.netstack.InjectInbound(nicName, pkt.Data); err != nil {
				log.Printf("router: inject failed: %v", err)
			}
		}
		return
	}

	if ttlIdx >= 0 {
		pkt.Data[ttlIdx]--
		if pkt.Data[ttlIdx] == 0 {
			return
		}
		if version == 4 {
			pkt.Data[10] = 0
			pkt.Data[11] = 0
			cs := checksum(pkt.Data[:20])
			pkt.Data[10] = byte(cs >> 8)
			pkt.Data[11] = byte(cs)
		}
	}

	entry := r.fib.Lookup(dstIP)
	if entry == nil {
		log.Printf("router: no route for %s", dstIP)
		return
	}

	r.forwardByFIB(pkt, entry)
}

func (r *Router) handleMPLSPacket(pkt transport.Packet) {
	if r.lfib == nil {
		log.Printf("router: MPLS packet dropped (no LFIB)")
		return
	}
	label, payload, err := mpls.PopLabel(pkt.Data)
	if err != nil {
		log.Printf("router: mpls pop label: %v", err)
		return
	}

	entry := r.lfib.Lookup(label)
	if entry == nil {
		log.Printf("router: no LFIB entry for label %d", label)
		return
	}

	switch entry.Op {
	case mpls.OpPop, mpls.OpPHP:
		nextType := detectPacketType(payload)
		r.handlePacket(transport.Packet{
			Type:      nextType,
			Data:      payload,
			Transport: pkt.Transport,
		})

	case mpls.OpSwap:
		if err := mpls.SwapLabel(pkt.Data, entry.OutLabels[0]); err != nil {
			log.Printf("router: swap label: %v", err)
			return
		}
		r.mu.RLock()
		t, ok := r.transports[entry.Transport]
		r.mu.RUnlock()
		if !ok {
			log.Printf("router: transport %s not found for label swap", entry.Transport)
			return
		}
		if err := t.Write(pkt); err != nil {
			log.Printf("router: write to %s failed: %v", entry.Transport, err)
		}

	case mpls.OpPush:
		pkt.Data = mpls.PushLabels(payload, entry.OutLabels)
		r.mu.RLock()
		t, ok := r.transports[entry.Transport]
		r.mu.RUnlock()
		if !ok {
			log.Printf("router: transport %s not found for label push", entry.Transport)
			return
		}
		if err := t.Write(pkt); err != nil {
			log.Printf("router: write to %s failed: %v", entry.Transport, err)
		}
	}
}

func detectPacketType(data []byte) transport.PacketType {
	if len(data) < 1 {
		return transport.PacketIP
	}
	v := data[0] >> 4
	if v == 4 || v == 6 {
		return transport.PacketIP
	}
	if mpls.HasLabel(data) {
		return transport.PacketMPLS
	}
	return transport.PacketIP
}

func (r *Router) forwardByFIB(pkt transport.Packet, entry *FIBEntry) {
	transportName := entry.Transport
	if transportName == "" && entry.NextHop.IsValid() {
		transportName, _ = r.nexthop.Resolve(entry.NextHop)
	}
	if transportName == "" && pkt.Transport != "" {
		transportName = pkt.Transport
	}
	switch entry.Action {
	case ActionLocal:
		nicName := entry.Transport
		if nicName == "" {
			nicName, _ = r.nicForAddr(entry.NextHop)
		}
		if nicName == "" {
			nicName = pkt.Transport
		}
		if err := r.netstack.InjectInbound(nicName, pkt.Data); err != nil {
			log.Printf("router: inject failed: %v", err)
		}
	case ActionForward:
		r.mu.RLock()
		t, ok := r.transports[transportName]
		r.mu.RUnlock()
		if !ok {
			log.Printf("router: transport %s not found", transportName)
			return
		}
		if err := t.Write(pkt); err != nil {
			log.Printf("router: write to %s failed: %v", transportName, err)
		}
	case ActionPush:
		pkt.Data = mpls.PushLabels(pkt.Data, entry.OutLabels)
		pkt.Type = transport.PacketMPLS
		r.mu.RLock()
		t, ok := r.transports[transportName]
		r.mu.RUnlock()
		if !ok {
			log.Printf("router: transport %s not found", transportName)
			return
		}
		if err := t.Write(pkt); err != nil {
			log.Printf("router: write to %s failed: %v", transportName, err)
		}
	}
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
