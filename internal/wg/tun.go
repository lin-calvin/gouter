package wg

import (
	"io"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

type MemTUN struct {
	Inbound  chan []byte
	Outbound chan []byte
	closed   chan struct{}
	events   chan tun.Event
	name     string
	mtu      int
}

func NewMemTUN(name string, mtu int) *MemTUN {
	t := &MemTUN{
		Inbound:  make(chan []byte, 256),
		Outbound: make(chan []byte, 256),
		closed:   make(chan struct{}),
		events:   make(chan tun.Event, 1),
		name:     name,
		mtu:      mtu,
	}
	t.events <- tun.EventUp
	return t
}

func (t *MemTUN) TUN() tun.Device {
	return &memTUNDev{t: t}
}

type memTUNDev struct {
	t *MemTUN
}

func (d *memTUNDev) File() *os.File { return nil }

func (d *memTUNDev) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-d.t.closed:
		return 0, os.ErrClosed
	case pkt := <-d.t.Outbound:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	}
}

func (d *memTUNDev) Write(bufs [][]byte, offset int) (int, error) {
	if offset == -1 {
		select {
		case <-d.t.closed:
		default:
			close(d.t.closed)
			close(d.t.events)
		}
		return 0, io.EOF
	}

	select {
	case <-d.t.closed:
		return 0, os.ErrClosed
	default:
	}

	for i, buf := range bufs {
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		select {
		case <-d.t.closed:
			return i, os.ErrClosed
		case d.t.Inbound <- pkt:
		}
	}
	return len(bufs), nil
}

func (d *memTUNDev) MTU() (int, error)        { return d.t.mtu, nil }
func (d *memTUNDev) Name() (string, error)    { return d.t.name, nil }
func (d *memTUNDev) Events() <-chan tun.Event { return d.t.events }
func (d *memTUNDev) BatchSize() int { return 1 }

func (d *memTUNDev) Close() error {
	_, _ = d.Write(nil, -1)
	return nil
}

func (t *MemTUN) Close() {
	t.TUN().Close()
}
