package mpls

import (
	"log"
	"net"
	"net/netip"

	"gouter/internal/transport"
)

type UDPTransport struct {
	name      string
	conn      *net.UDPConn
	localAddr netip.AddrPort
	reader    chan transport.Packet
	peers     map[netip.Addr]netip.AddrPort

	closeCh chan struct{}
}

func NewUDPTransport(name string, localAddr netip.AddrPort) (*UDPTransport, error) {
	udpAddr := net.UDPAddrFromAddrPort(localAddr)
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	t := &UDPTransport{
		name:      name,
		conn:      conn,
		localAddr: localAddr,
		reader:    make(chan transport.Packet, 256),
		peers:     make(map[netip.Addr]netip.AddrPort),
		closeCh:   make(chan struct{}),
	}
	go t.readLoop()
	return t, nil
}

func (t *UDPTransport) Name() string { return t.name }
func (t *UDPTransport) MTU() int     { return 1500 - 8 - 20 }

func (t *UDPTransport) Read() <-chan transport.Packet { return t.reader }

func (t *UDPTransport) Write(pkt transport.Packet) error {
	if pkt.Type != transport.PacketMPLS {
		return nil
	}

	ipHdr := pkt.Data[0:0]
	if !HasLabel(pkt.Data) {
		log.Printf("mpls-udp: write: no MPLS label found")
		return nil
	}

	return t.sendRaw(pkt.Data, ipHdr)
}

func (t *UDPTransport) Close() error {
	close(t.closeCh)
	return t.conn.Close()
}

func (t *UDPTransport) AddPeer(addr netip.Addr, peerAddr netip.AddrPort) {
	t.peers[addr] = peerAddr
}

func (t *UDPTransport) RemovePeer(addr netip.Addr) {
	delete(t.peers, addr)
}

func (t *UDPTransport) sendRaw(data []byte, _ []byte) error {
	if len(t.peers) == 0 {
		log.Printf("mpls-udp: no peers configured")
		return nil
	}

	for _, peerAddr := range t.peers {
		udpAddr := net.UDPAddrFromAddrPort(peerAddr)
		_, err := t.conn.WriteToUDP(data, udpAddr)
		if err != nil {
			log.Printf("mpls-udp: write to %s: %v", peerAddr, err)
			continue
		}
		return nil
	}
	return nil
}

func (t *UDPTransport) readLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-t.closeCh:
			return
		default:
		}
		n, _, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-t.closeCh:
				return
			default:
				log.Printf("mpls-udp: read: %v", err)
				continue
			}
		}
		if n < LabelEntrySize {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		t.reader <- transport.Packet{
			Type:      transport.PacketMPLS,
			Data:      pkt,
			Transport: t.name,
		}
	}
}

var _ = netip.AddrPort{}
