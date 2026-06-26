package mpls

import (
	"fmt"
)

const (
	LabelReservedMin = 0
	LabelReservedMax = 15
	LabelMax         = 0xFFFFF
	LabelEntrySize   = 4

	// MPLS-in-IP protocol number (RFC 4023)
	IPProtoMPLS = 137

	// EtherType for MPLS unicast
	EtherTypeMPLS = 0x8847
)

func ParseLabel(data []byte) (label uint32, tc uint8, bottom bool, ttl uint8, err error) {
	if len(data) < LabelEntrySize {
		return 0, 0, false, 0, fmt.Errorf("mpls: data too short: %d < %d", len(data), LabelEntrySize)
	}
	v := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	label = v >> 4
	tc = uint8((v >> 1) & 0x7)
	bottom = (v & 0x01) == 0x01
	ttl = data[3]
	return
}

func EncodeLabel(label uint32, tc uint8, bottom bool, ttl uint8) []byte {
	if label > LabelMax {
		label = LabelMax
	}
	v := (label << 4) | (uint32(tc) << 1)
	if bottom {
		v |= 0x01
	}
	return []byte{
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
		ttl,
	}
}

func BottomOfStack(label uint32) []byte {
	return EncodeLabel(label, 0, true, 255)
}

func NonBottomOfStack(label uint32) []byte {
	return EncodeLabel(label, 0, false, 255)
}

func PushLabel(pkt []byte, label uint32) []byte {
	enc := EncodeLabel(label, 0, true, 64)
	out := make([]byte, len(enc)+len(pkt))
	copy(out, enc)
	copy(out[len(enc):], pkt)
	return out
}

func PopLabel(pkt []byte) (label uint32, payload []byte, err error) {
	label, _, _, _, err = ParseLabel(pkt)
	if err != nil {
		return 0, nil, err
	}
	return label, pkt[LabelEntrySize:], nil
}

func SwapLabel(pkt []byte, newLabel uint32) error {
	if len(pkt) < LabelEntrySize {
		return fmt.Errorf("mpls: data too short to swap: %d < %d", len(pkt), LabelEntrySize)
	}
	enc := EncodeLabel(newLabel, 0, true, 64)
	copy(pkt[:LabelEntrySize], enc)
	return nil
}

func PushLabels(pkt []byte, labels []uint32) []byte {
	for i := len(labels) - 1; i >= 0; i-- {
		pkt = PushLabel(pkt, labels[i])
	}
	return pkt
}

func HasLabel(pkt []byte) bool {
	return len(pkt) >= LabelEntrySize
}

func IsMPLSOverIP(protocol byte) bool {
	return protocol == IPProtoMPLS
}
