package router

import (
	"net/netip"
	"sync"
)

type FIBAction uint8

const (
	ActionForward FIBAction = iota
	ActionPush
	ActionLocal
)

type FIBEntry struct {
	Prefix    netip.Prefix
	NextHop   netip.Addr
	Transport string
	Action    FIBAction
	OutLabels []uint32
}

type FIB struct {
	mu     sync.RWMutex
	routes []FIBEntry
}

func NewFIB() *FIB {
	return &FIB{
		routes: make([]FIBEntry, 0),
	}
}

func (f *FIB) Add(entry FIBEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, e := range f.routes {
		if e.Prefix == entry.Prefix {
			f.routes[i] = entry
			f.sort()
			return
		}
	}
	f.routes = append(f.routes, entry)
	f.sort()
}

func (f *FIB) Remove(prefix netip.Prefix) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, e := range f.routes {
		if e.Prefix == prefix {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
			return
		}
	}
}

func (f *FIB) Lookup(addr netip.Addr) *FIBEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var best *FIBEntry
	var bestLen int = -1
	for i := range f.routes {
		if f.routes[i].Prefix.Contains(addr) {
			if f.routes[i].Prefix.Bits() > bestLen {
				bestLen = f.routes[i].Prefix.Bits()
				best = &f.routes[i]
			}
		}
	}
	return best
}

func (f *FIB) List() []FIBEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]FIBEntry, len(f.routes))
	copy(result, f.routes)
	return result
}

func (f *FIB) sort() {
	for i := 0; i < len(f.routes); i++ {
		for j := i + 1; j < len(f.routes); j++ {
			if f.routes[j].Prefix.Bits() > f.routes[i].Prefix.Bits() {
				f.routes[i], f.routes[j] = f.routes[j], f.routes[i]
			}
		}
	}
}
