package mpls

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

type LabelOp uint8

const (
	OpPop  LabelOp = iota
	OpSwap
	OpPush
	OpPHP
)

type LFIBEntry struct {
	InLabel   uint32
	Op        LabelOp
	OutLabels []uint32
	NextHop   netip.Addr
	Transport string
}

type LFIB struct {
	mu      sync.RWMutex
	entries map[uint32]*LFIBEntry
	alloc   *LabelAllocator
}

func NewLFIB() *LFIB {
	return &LFIB{
		entries: make(map[uint32]*LFIBEntry),
		alloc:   NewLabelAllocator(),
	}
}

func (l *LFIB) Lookup(label uint32) *LFIBEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.entries[label]
}

func (l *LFIB) Add(entry LFIBEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := entry
	l.entries[entry.InLabel] = &e
}

func (l *LFIB) Remove(inLabel uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, inLabel)
}

func (l *LFIB) Allocate() uint32 {
	return l.alloc.Allocate()
}

func (l *LFIB) Release(label uint32) {
	l.alloc.Release(label)
}

func (l *LFIB) List() []LFIBEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]LFIBEntry, 0, len(l.entries))
	for _, e := range l.entries {
		result = append(result, *e)
	}
	return result
}

type LabelAllocator struct {
	next uint64
}

func NewLabelAllocator() *LabelAllocator {
	return &LabelAllocator{next: uint64(LabelReservedMax + 1)}
}

func (a *LabelAllocator) Allocate() uint32 {
	for {
		v := atomic.AddUint64(&a.next, 1)
		label := uint32(v)
		if label > LabelMax {
			atomic.StoreUint64(&a.next, uint64(LabelReservedMax+1))
			continue
		}
		if label <= LabelReservedMax {
			continue
		}
		return label
	}
}

func (a *LabelAllocator) Release(label uint32) {
	// simple allocator doesn't track individual labels
	_ = label
}
