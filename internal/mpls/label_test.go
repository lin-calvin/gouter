package mpls

import (
	"bytes"
	"testing"
)

func TestEncodeLabel(t *testing.T) {
	enc := EncodeLabel(100, 0, true, 64)
	if len(enc) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(enc))
	}
	label, tc, bottom, ttl, err := ParseLabel(enc)
	if err != nil {
		t.Fatalf("ParseLabel: %v", err)
	}
	if label != 100 {
		t.Errorf("label = %d, want 100", label)
	}
	if tc != 0 {
		t.Errorf("tc = %d, want 0", tc)
	}
	if !bottom {
		t.Errorf("bottom = false, want true")
	}
	if ttl != 64 {
		t.Errorf("ttl = %d, want 64", ttl)
	}
}

func TestEncodeLabelMax(t *testing.T) {
	enc := EncodeLabel(LabelMax, 7, true, 255)
	label, _, _, _, _ := ParseLabel(enc)
	if label != LabelMax {
		t.Errorf("label = %d, want %d", label, LabelMax)
	}
}

func TestEncodeLabelOverflow(t *testing.T) {
	enc := EncodeLabel(LabelMax+1, 0, false, 128)
	label, _, _, _, _ := ParseLabel(enc)
	if label != LabelMax {
		t.Errorf("label = %d, want clamped to %d", label, LabelMax)
	}
}

func TestParseLabelShort(t *testing.T) {
	_, _, _, _, err := ParseLabel([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestBottomOfStack(t *testing.T) {
	enc := BottomOfStack(200)
	_, _, bottom, _, _ := ParseLabel(enc)
	if !bottom {
		t.Error("BottomOfStack should set bottom=true")
	}
}

func TestNonBottomOfStack(t *testing.T) {
	enc := NonBottomOfStack(200)
	_, _, bottom, _, _ := ParseLabel(enc)
	if bottom {
		t.Error("NonBottomOfStack should set bottom=false")
	}
}

func TestPushLabel(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00}
	out := PushLabel(payload, 42)
	if len(out) != len(payload)+4 {
		t.Fatalf("len = %d, want %d", len(out), len(payload)+4)
	}
	label, rest, err := PopLabel(out)
	if err != nil {
		t.Fatalf("PopLabel: %v", err)
	}
	if label != 42 {
		t.Errorf("label = %d, want 42", label)
	}
	if !bytes.Equal(rest, payload) {
		t.Error("payload mismatch after push+pop")
	}
}

func TestPopLabel(t *testing.T) {
	payload := []byte("hello world")
	pkt := PushLabel(payload, 77)
	label, rest, err := PopLabel(pkt)
	if err != nil {
		t.Fatalf("PopLabel: %v", err)
	}
	if label != 77 {
		t.Errorf("label = %d, want 77", label)
	}
	if !bytes.Equal(rest, payload) {
		t.Error("payload mismatch")
	}
}

func TestSwapLabel(t *testing.T) {
	payload := []byte("test data")
	pkt := PushLabel(payload, 10)
	if err := SwapLabel(pkt, 20); err != nil {
		t.Fatalf("SwapLabel: %v", err)
	}
	label, rest, err := PopLabel(pkt)
	if err != nil {
		t.Fatalf("PopLabel: %v", err)
	}
	if label != 20 {
		t.Errorf("swap label = %d, want 20", label)
	}
	if !bytes.Equal(rest, payload) {
		t.Error("payload modified during swap")
	}
}

func TestSwapLabelShort(t *testing.T) {
	err := SwapLabel([]byte{0x00, 0x01}, 10)
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestPushLabels(t *testing.T) {
	payload := []byte{0x45}
	out := PushLabels(payload, []uint32{10, 20, 30})
	if len(out) != len(payload)+12 {
		t.Fatalf("len = %d, want %d", len(out), len(payload)+12)
	}

	l1, rest, _ := PopLabel(out)
	if l1 != 10 {
		t.Errorf("top label = %d, want 10", l1)
	}
	l2, rest, _ := PopLabel(rest)
	if l2 != 20 {
		t.Errorf("second label = %d, want 20", l2)
	}
	l3, rest, _ := PopLabel(rest)
	if l3 != 30 {
		t.Errorf("third label = %d, want 30", l3)
	}
	if !bytes.Equal(rest, payload) {
		t.Error("payload mismatch")
	}
}

func TestHasLabel(t *testing.T) {
	if HasLabel([]byte{}) {
		t.Error("empty slice should not have label")
	}
	if HasLabel([]byte{0x01, 0x02, 0x03}) {
		t.Error("3-byte slice should not have label")
	}
	if !HasLabel([]byte{0x00, 0x01, 0x02, 0x03}) {
		t.Error("4-byte slice should have label")
	}
}

func TestPushLabelsOrder(t *testing.T) {
	payload := []byte("data")
	out := PushLabels(payload, []uint32{100, 200})

	l1, rest, _ := PopLabel(out)
	if l1 != 100 {
		t.Errorf("first label = %d, want 100 (top of stack)", l1)
	}
	l2, _, _ := PopLabel(rest)
	if l2 != 200 {
		t.Errorf("second label = %d, want 200 (bottom of stack)", l2)
	}
}
