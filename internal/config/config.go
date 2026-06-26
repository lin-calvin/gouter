package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	BGP       BGPConfig       `yaml:"bgp"`
	WireGuard []WireGuardConf `yaml:"wireguard"`
	MPLS      *MPLSConfig     `yaml:"mpls"`
	Netstack  NetstackConf    `yaml:"netstack"`
}

type BGPConfig struct {
	ASN          uint32        `yaml:"asn"`
	RouterID     string        `yaml:"router_id"`
	ImportFilter []string      `yaml:"import_filter"`
	Peers        []BGPPeer     `yaml:"peers"`
	LocalRoutes  []LocalRoute  `yaml:"local_routes"`
	SRPolicies   []SRPolicy    `yaml:"sr_policies"`
}

type BGPPeer struct {
	Name        string   `yaml:"name"`
	Address     string   `yaml:"address"`
	ASN         uint32   `yaml:"asn"`
	PeerBGPPort uint16   `yaml:"peer_bgp_port"`
	Families    []string `yaml:"families"`
}

type LocalRoute struct {
	Prefix  string `yaml:"prefix"`
	NextHop string `yaml:"next_hop"`
	Label   bool   `yaml:"label"`
}

type SRPolicy struct {
	Endpoint string   `yaml:"endpoint"`
	Color    uint32   `yaml:"color"`
	Segments []uint32 `yaml:"segments"`
}

type WireGuardConf struct {
	Name       string       `yaml:"name"`
	ListenPort int          `yaml:"listen_port"`
	PrivateKey string       `yaml:"private_key"`
	Address    string       `yaml:"address"`
	MTU        int          `yaml:"mtu"`
	Peers      []WGPeerConf `yaml:"peers"`
}

type WGPeerConf struct {
	PublicKey  string `yaml:"public_key"`
	Endpoint   string `yaml:"endpoint"`
	AllowedIPs string `yaml:"allowed_ips"`
}

type MPLSConfig struct {
	UDP MPLSUDP `yaml:"udp"`
}

type MPLSUDP struct {
	ListenPort int      `yaml:"listen_port"`
	Peers      []string `yaml:"peers"`
}

type NetstackConf struct {
	TCPPort int `yaml:"tcp_port"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Netstack.TCPPort == 0 {
		cfg.Netstack.TCPPort = 8080
	}
	for i := range cfg.WireGuard {
		if cfg.WireGuard[i].MTU == 0 {
			cfg.WireGuard[i].MTU = 1420
		}
	}

	return &cfg, nil
}

func B64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
