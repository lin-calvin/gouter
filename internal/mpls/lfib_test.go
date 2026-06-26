package mpls

import (
	"net/netip"
	"testing"
)

func TestLFIBLookup(t *testing.T) {
	lfib := NewLFIB()

	lfib.Add(LFIBEntry{
		InLabel:   100,
		Op:        OpSwap,
		OutLabels: []uint32{200},
		NextHop:   netip.MustParseAddr("10.0.0.1"),
		Transport: "wg-a",
	})

	entry := lfib.Lookup(100)
	if entry == nil {
		t.Fatal("entry not found")
	}
	if entry.InLabel != 100 {
		t.Errorf("InLabel = %d, want 100", entry.InLabel)
	}
	if entry.Op != OpSwap {
		t.Errorf("Op = %d, want OpSwap", entry.Op)
	}
	if len(entry.OutLabels) != 1 || entry.OutLabels[0] != 200 {
		t.Errorf("OutLabels = %v, want [200]", entry.OutLabels)
	}
	if entry.NextHop.String() != "10.0.0.1" {
		t.Errorf("NextHop = %s, want 10.0.0.1", entry.NextHop)
	}
}

func TestLFIBLookupMissing(t *testing.T) {
	lfib := NewLFIB()
	entry := lfib.Lookup(999)
	if entry != nil {
		t.Error("expected nil for missing label")
	}
}

func TestLFIBRemove(t *testing.T) {
	lfib := NewLFIB()
	lfib.Add(LFIBEntry{InLabel: 50, Op: OpPop})
	lfib.Remove(50)
	if lfib.Lookup(50) != nil {
		t.Error("entry should have been removed")
	}
}

func TestLFIBPop(t *testing.T) {
	lfib := NewLFIB()
	lfib.Add(LFIBEntry{
		InLabel: 16,
		Op:      OpPop,
	})

	entry := lfib.Lookup(16)
	if entry == nil {
		t.Fatal("entry not found")
	}
	if entry.Op != OpPop {
		t.Errorf("Op = %d, want OpPop", entry.Op)
	}
}

func TestLFIBPHP(t *testing.T) {
	lfib := NewLFIB()
	lfib.Add(LFIBEntry{
		InLabel: 3,
		Op:      OpPHP,
	})

	entry := lfib.Lookup(3)
	if entry == nil {
		t.Fatal("entry not found")
	}
	if entry.Op != OpPHP {
		t.Errorf("Op = %d, want OpPHP", entry.Op)
	}
}

func TestLabelAllocator(t *testing.T) {
	alloc := NewLabelAllocator()

	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		label := alloc.Allocate()
		if label <= LabelReservedMax {
			t.Errorf("allocated reserved label %d", label)
		}
		if label > LabelMax {
			t.Errorf("label %d exceeds max %d", label, LabelMax)
		}
		if seen[label] {
			t.Errorf("duplicate label %d", label)
		}
		seen[label] = true
	}
}

func TestLabelAllocatorReserved(t *testing.T) {
	alloc := NewLabelAllocator()
	for i := 0; i < 10; i++ {
		label := alloc.Allocate()
		if label <= LabelReservedMin || label <= 15 {
			t.Errorf("label %d should not be in reserved range", label)
		}
	}
}

func TestLFIBAddUpdate(t *testing.T) {
	lfib := NewLFIB()
	lfib.Add(LFIBEntry{InLabel: 10, Op: OpPop})
	lfib.Add(LFIBEntry{InLabel: 10, Op: OpSwap, OutLabels: []uint32{20}})

	entry := lfib.Lookup(10)
	if entry.Op != OpSwap {
		t.Errorf("Op = %d, want OpSwap after update", entry.Op)
	}
}

func TestLFIBList(t *testing.T) {
	lfib := NewLFIB()
	lfib.Add(LFIBEntry{InLabel: 1, Op: OpPop})
	lfib.Add(LFIBEntry{InLabel: 2, Op: OpSwap})

	list := lfib.List()
	if len(list) != 2 {
		t.Errorf("len = %d, want 2", len(list))
	}
}

func TestLFIBConcurrency(t *testing.T) {
	lfib := NewLFIB()
	alloc := NewLabelAllocator()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				label := alloc.Allocate()
				lfib.Add(LFIBEntry{
					InLabel: label,
					Op:      OpPop,
				})
				entry := lfib.Lookup(label)
				if entry == nil {
					t.Errorf("entry not found for label %d", label)
				}
				lfib.Remove(label)
			}
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
