package bgp

import (
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"gouter/internal/netstack"
)

type PeerProxy struct {
	Name         string
	PeerAddr     netip.Addr
	PeerPort     uint16
	LocalIP      netip.Addr
	OutboundPort uint16
}

type ProxyManager struct {
	ns        *netstack.Manager
	gobgpPort uint16

	proxies   map[netip.Addr]*PeerProxy
	listeners map[netip.Addr]net.Listener

	nextIP   netip.Addr
	nextPort uint16
	mu       sync.Mutex

	inboundLns []net.Listener
}

func NewProxyManager(ns *netstack.Manager, gobgpPort uint16, startIP netip.Addr, startPort uint16) *ProxyManager {
	if !startIP.IsValid() {
		startIP = netip.MustParseAddr("127.0.0.2")
	}
	if startPort == 0 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			startPort = uint16(ln.Addr().(*net.TCPAddr).Port)
			ln.Close()
		} else {
			startPort = 11001
		}
	}
	return &ProxyManager{
		ns:        ns,
		gobgpPort: gobgpPort,
		proxies:   make(map[netip.Addr]*PeerProxy),
		listeners: make(map[netip.Addr]net.Listener),
		nextIP:    startIP,
		nextPort:  startPort,
	}
}

func (pm *ProxyManager) CreateProxy(name string, peerAddr netip.Addr, peerPort uint16) (*PeerProxy, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if existing, ok := pm.proxies[peerAddr]; ok {
		return existing, nil
	}

	localIP := pm.nextIP
	pm.nextIP = pm.nextIP.Next()

	outboundPort := pm.nextPort
	pm.nextPort++

	proxy := &PeerProxy{
		Name:         name,
		PeerAddr:     peerAddr,
		PeerPort:     peerPort,
		LocalIP:      localIP,
		OutboundPort: outboundPort,
	}

	addr := net.JoinHostPort(localIP.String(), strconv.Itoa(int(outboundPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	pm.listeners[localIP] = ln
	pm.proxies[peerAddr] = proxy

	go pm.runOutbound(ln, proxy)
	return proxy, nil
}

func (pm *ProxyManager) StartInbound(ctx context.Context) error {
	v4ln, v6ln, err := pm.ns.ListenTCPv4v6(179)
	if err != nil {
		return err
	}
	pm.inboundLns = []net.Listener{v4ln}
	go pm.runInbound(ctx, v4ln)
	if v6ln != nil {
		pm.inboundLns = append(pm.inboundLns, v6ln)
		go pm.runInbound(ctx, v6ln)
	}
	return nil
}

func (pm *ProxyManager) runOutbound(ln net.Listener, proxy *PeerProxy) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go pm.handleOutbound(conn, proxy)
	}
}

func (pm *ProxyManager) handleOutbound(kernelConn net.Conn, proxy *PeerProxy) {
	defer kernelConn.Close()

	addrPort := netip.AddrPortFrom(proxy.PeerAddr, proxy.PeerPort)
	peerConn, err := pm.ns.DialTCP(context.Background(), addrPort)
	if err != nil {
		log.Printf("proxy[%s]: dial peer %s: %v", proxy.Name, addrPort, err)
		return
	}
	defer peerConn.Close()

	log.Printf("proxy[%s]: outbound gobgp → %s", proxy.Name, addrPort)
	pipe(kernelConn, peerConn)
}

func (pm *ProxyManager) runInbound(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("proxy: inbound accept: %v", err)
			continue
		}
		go pm.handleInbound(conn)
	}
}

func (pm *ProxyManager) handleInbound(peerConn net.Conn) {
	remoteIP, err := netip.ParseAddrPort(peerConn.RemoteAddr().String())
	if err != nil {
		log.Printf("proxy: parse remote %s: %v", peerConn.RemoteAddr(), err)
		peerConn.Close()
		return
	}

	pm.mu.Lock()
	proxy, ok := pm.proxies[remoteIP.Addr()]
	pm.mu.Unlock()
	if !ok {
		log.Printf("proxy: unknown peer %s, dropping", remoteIP.Addr())
		peerConn.Close()
		return
	}

	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: proxy.LocalIP.AsSlice()},
	}
	gobgpAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(pm.gobgpPort)))
	kernelConn, err := dialer.Dial("tcp", gobgpAddr)
	if err != nil {
		log.Printf("proxy[%s]: dial gobgp: %v", proxy.Name, err)
		peerConn.Close()
		return
	}
	defer kernelConn.Close()

	log.Printf("proxy[%s]: inbound %s → gobgp", proxy.Name, remoteIP.Addr())
	// Don't close peerConn on gobgp collision — let the peer handle it
	go io.Copy(peerConn, kernelConn)
	io.Copy(kernelConn, peerConn)
}

func (pm *ProxyManager) Close() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, ln := range pm.listeners {
		ln.Close()
	}
	for _, ln := range pm.inboundLns {
		ln.Close()
	}
}

func (pm *ProxyManager) GetProxy(peerAddr netip.Addr) *PeerProxy {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.proxies[peerAddr]
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}
