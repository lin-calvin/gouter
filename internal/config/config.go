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
	Links     []LinkConfig    `yaml:"links"`
	Routes    []RouteConfig   `yaml:"routes"`
	Netstack  NetstackConf    `yaml:"netstack"`
}

type BGPConfig struct {
	ASN          uint32   `yaml:"asn"`
	RouterID     string   `yaml:"router_id"`
	ImportFilter []string `yaml:"import_filter"`
	Peers        []BGPPeer `yaml:"peers"`
}

type BGPPeer struct {
	Name        string   `yaml:"name"`
	Address     string   `yaml:"address"`
	ASN         uint32   `yaml:"asn"`
	PeerBGPPort uint16   `yaml:"peer_bgp_port"`
	Families    []string `yaml:"families"`
}

type RouteConfig struct {
	Prefix   string   `yaml:"prefix"`
	NextHop  string   `yaml:"next_hop"`
	Export   bool     `yaml:"export"`
	InLabel  uint32   `yaml:"in_label,omitempty"`
	Labels   []uint32 `yaml:"labels,omitempty"`
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

type LinkConfig struct {
	Name    string         `yaml:"name"`
	WG      *WGLinkConfig  `yaml:"wireguard,omitempty"`
	MPLSUDP *MPLSUDPLink   `yaml:"mpls_udp,omitempty"`
	LS      *LinkLSConfig  `yaml:"ls,omitempty"`
}

type WGLinkConfig struct {
	ListenPort int    `yaml:"listen_port"`
	PrivateKey string `yaml:"private_key"`
	Address    string `yaml:"address"`
	MTU        int    `yaml:"mtu"`
	PublicKey  string `yaml:"public_key"`
	Endpoint   string `yaml:"endpoint"`
	AllowedIPs string `yaml:"allowed_ips"`
}

type MPLSUDPLink struct {
	ListenPort int      `yaml:"listen_port"`
	Peers      []string `yaml:"peers"`
}

type LinkLSConfig struct {
	RemoteRouterID string `yaml:"remote_router_id"`
	RemoteASN      uint32 `yaml:"remote_asn"`
	Metric         uint32 `yaml:"metric"`
	AdjSID         uint32 `yaml:"adj_sid"`
}

type MPLSBase struct {
	SRGBStart uint32 `yaml:"srgb_start"`
	SRGBEnd   uint32 `yaml:"srgb_end"`
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
	for i := range cfg.Links {
		if cfg.Links[i].WG != nil && cfg.Links[i].WG.MTU == 0 {
			cfg.Links[i].WG.MTU = 1420
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
