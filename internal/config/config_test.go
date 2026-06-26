package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	yaml := `
bgp:
  asn: 4242420001
  router_id: "10.0.1.1"
  listen_port: 179
  peers:
    - name: "dn42-a"
      address: "10.0.1.2"
      asn: 4242420002
      families: ["ipv4-unicast", "ipv4-labelled-unicast"]
    - name: "internal-1"
      address: "10.0.2.2"
      asn: 4242420001
      families: ["ipv4-unicast", "ipv4-labelled-unicast"]
wireguard:
  - name: "wg-a"
    listen_port: 51820
    private_key: "base64key"
    address: "10.0.1.1/24"
    mtu: 1420
    peers:
      - public_key: "base64peer"
        endpoint: "1.2.3.4:51820"
        allowed_ips: "10.0.1.2/32"
netstack:
  tcp_port: 8080
`
	path := "/tmp/gouter-test-config.yaml"
	os.WriteFile(path, []byte(yaml), 0644)
	defer os.Remove(path)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.BGP.ASN != 4242420001 {
		t.Errorf("asn = %d", cfg.BGP.ASN)
	}
	if cfg.BGP.RouterID != "10.0.1.1" {
		t.Errorf("router_id = %s", cfg.BGP.RouterID)
	}
	if len(cfg.BGP.Peers) != 2 {
		t.Errorf("peers = %d, want 2", len(cfg.BGP.Peers))
	}
	if cfg.BGP.Peers[0].Name != "dn42-a" {
		t.Errorf("peer[0] = %s", cfg.BGP.Peers[0].Name)
	}
	if len(cfg.BGP.Peers[0].Families) != 2 {
		t.Errorf("families = %v", cfg.BGP.Peers[0].Families)
	}
	if len(cfg.WireGuard) != 1 {
		t.Errorf("wireguard = %d, want 1", len(cfg.WireGuard))
	}
	if cfg.Netstack.TCPPort != 8080 {
		t.Errorf("tcp_port = %d", cfg.Netstack.TCPPort)
	}
}

func TestLoadDefaults(t *testing.T) {
	yaml := `
bgp:
  asn: 65001
  router_id: "1.1.1.1"
wireguard:
  - name: "wg0"
    private_key: "key"
    address: "10.0.0.1/24"
`
	path := "/tmp/gouter-test-defaults.yaml"
	os.WriteFile(path, []byte(yaml), 0644)
	defer os.Remove(path)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.WireGuard[0].MTU != 1420 {
		t.Errorf("default mtu = %d", cfg.WireGuard[0].MTU)
	}
	if cfg.Netstack.TCPPort != 8080 {
		t.Errorf("default tcp_port = %d", cfg.Netstack.TCPPort)
	}
	if len(cfg.BGP.Peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(cfg.BGP.Peers))
	}
}

func TestB64ToHex(t *testing.T) {
	// "test" in base64 is "dGVzdA=="
	hex, err := B64ToHex("dGVzdA==")
	if err != nil {
		t.Fatalf("B64ToHex: %v", err)
	}
	if hex != "74657374" {
		t.Errorf("hex = %s, want 74657374", hex)
	}

	_, err = B64ToHex("!!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}
