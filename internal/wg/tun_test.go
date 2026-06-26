package wg

import (
	"testing"
	"time"
)

func TestMemTUNReadWrite(t *testing.T) {
	tun := NewMemTUN("test0", 1500)
	defer tun.Close()

	dev := tun.TUN()

	// Write a packet into the TUN (simulates WG decryption)
	testPkt := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00}
	bufs := [][]byte{make([]byte, 1500)}
	copy(bufs[0], testPkt)
	sizes := []int{0}
	n, err := dev.Write(bufs, len(testPkt))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}

	// Read it from Inbound channel
	select {
	case pkt := <-tun.Inbound:
		if len(pkt) != (1500 - len(testPkt)) {
			t.Errorf("len = %d, want %d", len(pkt), 1500-len(testPkt))
		}
	case <-time.After(time.Second):
		t.Fatal("timeout reading from Inbound")
	}

	// Write to Outbound (simulates injecting a packet to be encrypted)
	outPkt := []byte{0x45, 0x00, 0x00, 0x14}
	go func() {
		tun.Outbound <- outPkt
	}()

	bufs[0] = make([]byte, 1500)
	n, err = dev.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}
	if sizes[0] != len(outPkt) {
		t.Errorf("sizes[0] = %d, want %d", sizes[0], len(outPkt))
	}
}

func TestMemTUNMTU(t *testing.T) {
	tun := NewMemTUN("test0", 1420)
	defer tun.Close()

	dev := tun.TUN()
	mtu, err := dev.MTU()
	if err != nil {
		t.Fatalf("MTU: %v", err)
	}
	if mtu != 1420 {
		t.Errorf("mtu = %d, want 1420", mtu)
	}
}

func TestMemTUNName(t *testing.T) {
	tun := NewMemTUN("wg-test", 1500)
	defer tun.Close()

	dev := tun.TUN()
	name, err := dev.Name()
	if err != nil {
		t.Fatalf("Name: %v", err)
	}
	if name != "wg-test" {
		t.Errorf("name = %s, want wg-test", name)
	}
}

func TestMemTUNFile(t *testing.T) {
	tun := NewMemTUN("test0", 1500)
	defer tun.Close()

	dev := tun.TUN()
	f := dev.File()
	if f != nil {
		t.Error("File should return nil for MemTUN")
	}
}

func TestMemTUNBatchSize(t *testing.T) {
	tun := NewMemTUN("test0", 1500)
	defer tun.Close()

	dev := tun.TUN()
	if dev.BatchSize() != 1 {
		t.Errorf("BatchSize = %d, want 1", dev.BatchSize())
	}
}

func TestMemTUNEvents(t *testing.T) {
	tun := NewMemTUN("test0", 1500)
	defer tun.Close()

	dev := tun.TUN()

	select {
	case ev := <-dev.Events():
		_ = ev
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for EventUp")
	}
}

func TestMemTUNClose(t *testing.T) {
	tun := NewMemTUN("test0", 1500)
	dev := tun.TUN()

	err := dev.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read after close should return error
	bufs := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	_, err = dev.Read(bufs, sizes, 0)
	if err == nil {
		t.Error("Read after close should error")
	}
}

func TestMemTUNWriteAfterClose(t *testing.T) {
	tun := NewMemTUN("test0", 1500)
	dev := tun.TUN()

	dev.Close()

	_, err := dev.Write([][]byte{[]byte{0x45}}, 0)
	if err == nil {
		t.Error("Write after close should error")
	}
}

func TestMemTUNOffset(t *testing.T) {
	tun := NewMemTUN("test0", 1500)
	defer tun.Close()

	dev := tun.TUN()

	// Write with offset: simulate writing with a header at offset 14
	payload := []byte{0x45, 0x00, 0x00, 0x14}
	buf := make([]byte, 1500)
	copy(buf[14:], payload)
	n, err := dev.Write([][]byte{buf}, 14)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d", n)
	}

	select {
	case pkt := <-tun.Inbound:
		if len(pkt) != 1500-14 {
			t.Errorf("payload len = %d, want %d", len(pkt), 1500-14)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// Read with offset
	go func() {
		tun.Outbound <- payload
	}()

	buf2 := make([]byte, 1500)
	sizes2 := []int{0}
	n, err = dev.Read([][]byte{buf2}, sizes2, 14)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if sizes2[0] != len(payload) {
		t.Errorf("sizes[0] = %d, want %d", sizes2[0], len(payload))
	}
}
