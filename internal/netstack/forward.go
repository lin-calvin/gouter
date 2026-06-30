package netstack

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
)

type ForwardRule struct {
	Name      string
	ListenPort uint16  // port on netstack
	Target    string  // "127.0.0.1:port" — via kernel TCP
}

type activeFwd struct {
	rule ForwardRule
	ln   net.Listener
}

type ForwardManager struct {
	ns    *Manager
	fwd   map[string]*activeFwd
	mu    sync.Mutex
}

func NewForwardManager(ns *Manager) *ForwardManager {
	return &ForwardManager{
		ns:  ns,
		fwd: make(map[string]*activeFwd),
	}
}

func (fm *ForwardManager) Add(ctx context.Context, rule ForwardRule) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if _, ok := fm.fwd[rule.Name]; ok {
		return nil
	}

	ln, err := fm.ns.ListenTCP(rule.ListenPort)
	if err != nil {
		return err
	}

	af := &activeFwd{rule: rule, ln: ln}
	fm.fwd[rule.Name] = af
	go fm.run(ctx, af)
	log.Printf("forward %s: :%d → %s", rule.Name, rule.ListenPort, rule.Target)
	return nil
}

func (fm *ForwardManager) Remove(name string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	if af, ok := fm.fwd[name]; ok {
		af.ln.Close()
		delete(fm.fwd, name)
		log.Printf("forward %s: stopped", name)
	}
}

func (fm *ForwardManager) Close() {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	for _, af := range fm.fwd {
		af.ln.Close()
	}
	fm.fwd = nil
}

func (fm *ForwardManager) run(ctx context.Context, af *activeFwd) {
	for {
		conn, err := af.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("forward %s: accept: %v", af.rule.Name, err)
			continue
		}
		go fm.handle(conn, af.rule)
	}
}

func (fm *ForwardManager) handle(peerConn net.Conn, rule ForwardRule) {
	defer peerConn.Close()

	targetConn, err := net.Dial("tcp", rule.Target)
	if err != nil {
		log.Printf("forward %s: dial %s: %v", rule.Name, rule.Target, err)
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(targetConn, peerConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(peerConn, targetConn)
	}()
	wg.Wait()
}
