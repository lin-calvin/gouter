package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"gouter/internal/transport"
)

type NICConfig struct {
	Name    string
	Address netip.Prefix
	MTU     uint32
}

type Manager struct {
	stack     *stack.Stack
	nics      map[string]*channel.Endpoint
	nicNames  map[tcpip.NICID]string
	nicByAddr map[netip.Prefix]string
	nextNICID tcpip.NICID
	mu        sync.Mutex
}

func NewManager() *Manager {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	return &Manager{
		stack:     s,
		nics:      make(map[string]*channel.Endpoint),
		nicNames:  make(map[tcpip.NICID]string),
		nicByAddr: make(map[netip.Prefix]string),
		nextNICID: 1,
	}
}

func (m *Manager) AddNIC(cfg NICConfig) (*channel.Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	nicID := m.nextNICID
	m.nextNICID++

	linkAddr := tcpip.LinkAddress(macForNIC(nicID))
	ep := channel.New(256, cfg.MTU, linkAddr)
	if tcpErr := m.stack.CreateNIC(nicID, ep); tcpErr != nil {
		return nil, &net.OpError{Op: "create_nic", Err: errors.New(tcpErr.String())}
	}

	addr := netipToTcpipAddress(cfg.Address.Addr())
	netAddr := netipToTcpipAddress(cfg.Address.Masked().Addr())

	dup := false
	for _, existing := range m.nicByAddr {
		if existing == cfg.Name {
			continue
		}
	}
	for pfx := range m.nicByAddr {
		if pfx == cfg.Address {
			dup = true
			break
		}
	}

	if !dup {
		protocolAddr := tcpip.ProtocolAddress{
			Protocol: ipProtocolForAddress(cfg.Address.Addr()),
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: cfg.Address.Bits(),
			},
		}
		if tcpErr := m.stack.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); tcpErr != nil {
			return nil, &net.OpError{Op: "add_protocol_address", Err: errors.New(tcpErr.String())}
		}

		subnet, err := tcpip.NewSubnet(netAddr, tcpip.MaskFromBytes(net.CIDRMask(cfg.Address.Bits(), len(netAddr.AsSlice())*8)))
		if err != nil {
			return nil, err
		}
		m.stack.AddRoute(tcpip.Route{
			Destination: subnet,
			NIC:         nicID,
		})
	}

	m.nics[cfg.Name] = ep
	m.nicNames[nicID] = cfg.Name
	m.nicByAddr[cfg.Address] = cfg.Name
	return ep, nil
}

func (m *Manager) AddPeerRoute(nicName string, peerPrefix netip.Prefix, nextHop netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ep, ok := m.nics[nicName]
	if !ok {
		return &net.OpError{Op: "add_peer_route", Err: errors.New("nic not found")}
	}

	nicID := tcpip.NICID(0)
	for id, n := range m.nicNames {
		if n == nicName {
			nicID = id
			break
		}
	}
	if nicID == 0 {
		return &net.OpError{Op: "add_peer_route", Err: errors.New("nic id not found")}
	}
	_ = ep

	dest := netipToTcpipAddress(peerPrefix.Masked().Addr())
	mask := tcpip.MaskFromBytes(net.CIDRMask(peerPrefix.Bits(), len(dest.AsSlice())*8))
	subnet, err := tcpip.NewSubnet(dest, mask)
	if err != nil {
		return err
	}

	gateway := tcpip.Address{}
	if nextHop.IsValid() && nextHop != peerPrefix.Addr() {
		gateway = netipToTcpipAddress(nextHop)
	}

	m.stack.AddRoute(tcpip.Route{
		Destination: subnet,
		Gateway:     gateway,
		NIC:         nicID,
	})
	return nil
}

func (m *Manager) RemoveNIC(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.nics[name]
	if !ok {
		return
	}
	for id, n := range m.nicNames {
		if n == name {
			m.stack.RemoveNIC(id)
			delete(m.nicNames, id)
			break
		}
	}
	for pfx, n := range m.nicByAddr {
		if n == name {
			delete(m.nicByAddr, pfx)
		}
	}
	delete(m.nics, name)
}

func (m *Manager) InjectInbound(nicName string, ipPacket []byte) error {
	m.mu.Lock()
	ep, ok := m.nics[nicName]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("nic %s not found", nicName)
	}

	protocol := header.IPv4ProtocolNumber
	if len(ipPacket) > 0 {
		switch ipPacket[0] >> 4 {
		case 4:
			protocol = header.IPv4ProtocolNumber
		case 6:
			protocol = header.IPv6ProtocolNumber
		}
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ipPacket),
	})
	ep.InjectInbound(protocol, pkt)
	pkt.DecRef()
	return nil
}

func (m *Manager) GetNICOutChannel(ctx context.Context, name string) <-chan transport.Packet {
	m.mu.Lock()
	ep, ok := m.nics[name]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	out := make(chan transport.Packet, 256)
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			slices := pkt.AsSlices()
			var data []byte
			for _, s := range slices {
				data = append(data, s...)
			}
			pkt.DecRef()
			out <- transport.Packet{
				Type:      transport.PacketIP,
				Data:      data,
				Transport: name,
			}
		}
	}()
	return out
}

func (m *Manager) ListenTCP(port uint16) (net.Listener, error) {
	return m.ListenTCPProto(port, header.IPv4ProtocolNumber)
}

func (m *Manager) ListenTCPProto(port uint16, proto tcpip.NetworkProtocolNumber) (net.Listener, error) {
	listener, err := gonet.ListenTCP(m.stack, tcpip.FullAddress{
		Port: port,
	}, proto)
	if err != nil {
		return nil, &net.OpError{Op: "listen_tcp", Err: err}
	}
	return listener, nil
}

func (m *Manager) ListenTCPv4v6(port uint16) (v4, v6 net.Listener, err error) {
	v4, err = m.ListenTCPProto(port, header.IPv4ProtocolNumber)
	if err != nil {
		return nil, nil, err
	}
	v6, err = m.ListenTCPProto(port, header.IPv6ProtocolNumber)
	if err != nil {
		// IPv6 listener is optional — v4-only is fine
		return v4, nil, nil
	}
	return v4, v6, nil
}

func (m *Manager) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	protocol := header.IPv4ProtocolNumber
	if addr.Addr().Is6() {
		protocol = header.IPv6ProtocolNumber
	}
	return gonet.DialContextTCP(ctx, m.stack, tcpip.FullAddress{
		Addr: netipToTcpipAddress(addr.Addr()),
		Port: addr.Port(),
	}, protocol)
}

func (m *Manager) LocalAddresses() []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()

	nicsInfo := m.stack.NICInfo()
	var result []netip.Prefix
	for _, nic := range nicsInfo {
		for _, addr := range nic.ProtocolAddresses {
			ip, ok := netip.AddrFromSlice(addr.AddressWithPrefix.Address.AsSlice())
			if ok {
				result = append(result, netip.PrefixFrom(ip, addr.AddressWithPrefix.PrefixLen))
			}
		}
	}
	return result
}

func (m *Manager) IsLocalAddress(addr netip.Addr) bool {
	for _, pfx := range m.LocalAddresses() {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func (m *Manager) NICNameForAddress(addr netip.Addr) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for pfx, name := range m.nicByAddr {
		if pfx.Contains(addr) {
			return name, true
		}
	}
	return "", false
}

func netipToTcpipAddress(addr netip.Addr) tcpip.Address {
	if addr.Is4() || addr.Is4In6() {
		b := addr.As4()
		return tcpip.AddrFrom4(b)
	}
	b := addr.As16()
	return tcpip.AddrFrom16(b)
}

func ipProtocolForAddress(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is4() || addr.Is4In6() {
		return header.IPv4ProtocolNumber
	}
	return header.IPv6ProtocolNumber
}

func macForNIC(id tcpip.NICID) []byte {
	return []byte{0x02, 0x00, 0x00, 0x00, 0x00, byte(id)}
}
