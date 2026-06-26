package wg

import (
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"gouter/internal/transport"
)

const DefaultMTU = 1420

type Transport struct {
	name   string
	mtu    int
	tun    *MemTUN
	dev    *device.Device
	reader chan transport.Packet
	logger *device.Logger
}

func NewTransport(name string, mtu int, logLevel int) *Transport {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	t := &Transport{
		name:   name,
		mtu:    mtu,
		tun:    NewMemTUN(name, mtu),
		reader: make(chan transport.Packet, 256),
		logger: device.NewLogger(logLevel, "("+name+") "),
	}
	t.dev = device.NewDevice(t.tun.TUN(), conn.NewDefaultBind(), t.logger)
	return t
}

func (t *Transport) Name() string { return t.name }
func (t *Transport) MTU() int     { return t.mtu }

func (t *Transport) Read() <-chan transport.Packet {
	return t.reader
}

func (t *Transport) Write(pkt transport.Packet) error {
	select {
	case <-t.tun.closed:
		return tun.ErrTooManySegments
	case t.tun.Outbound <- pkt.Data:
		return nil
	}
}

func (t *Transport) Configure(uapiCfg string) error {
	return t.dev.IpcSet(uapiCfg)
}

func (t *Transport) Up() error {
	go t.readLoop()
	return t.dev.Up()
}

func (t *Transport) Close() error {
	t.tun.Close()
	t.dev.Close()
	return nil
}

func (t *Transport) readLoop() {
	for {
		select {
		case <-t.tun.closed:
			return
		case pkt := <-t.tun.Inbound:
			t.reader <- transport.Packet{
				Type:      transport.PacketIP,
				Data:      pkt,
				Transport: t.name,
			}
		}
	}
}
