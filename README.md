# gouter

A Golang based user-space IP+MPLS router with BGP support, perfect for tiny dn42 nodes.

## Features

- User-space router (no kernel modules required)
- Static routing and BGP
- MPLS switching (untested)
- WireGuard as link layer
- Simple YAML configuration
- Built-in TCP stack (for testing/demo)

## Quick Start

### Prerequisites

- Go 1.21+ (or latest)
- WireGuard tools (for key generation, e.g., `wg genkey`)

### Build

```bash
git clone https://github.com/lin-calvin/gouter.git
cd gouter
go build -o gouter .
```

### Run

```bash
./gouter config.yaml
```

## Configuration

### Example: static routing only

```yaml
routes:
  - prefix: "10.0.1.0/24"
    next_hop: "10.0.1.1"
    export: true               # export to BGP (ignored when BGP is disabled)

  - prefix: "10.0.2.1/32"
    next_hop: "10.0.2.1"
    export: false              # FIB entry only, never advertised

links:
  - name: "peer1"
    address: "10.0.1.1/32"
    peer_ip: "10.0.1.2"
    wireguard:
      listen_port: 51820
      private_key: "<base64-from-wg-genkey>"
      mtu: 1420
      public_key: "<base64-from-wg-pubkey>"
      endpoint: "peer.example.com:51820"
      allowed_ips: "10.0.1.2/32"
    # Optional link-state / IGP parameters (reserved for future use)
    # ls:
    #   remote_router_id: "10.0.2.1"
    #   remote_asn: 65002
    #   metric: 10
    #   adj_sid: 24001

  - name: "peer2"
    address: "10.0.2.1/32"
    peer_ip: "10.0.2.2"
    wireguard:
      listen_port: 51821
      private_key: "<base64-from-wg-genkey>"
      mtu: 1420
      public_key: "<base64-from-wg-pubkey>"
      endpoint: "internal.example.com:51821"
      allowed_ips: "10.0.2.2/32"

netstack:
  tcp_port: 8080               # starts a simple "hello world" HTTP server
```

### Generating WireGuard Keys

```bash
# Generate private key and derive public key
wg genkey | tee privatekey | wg pubkey > publickey
# Encode as base64 (one line) and paste into the configuration
```

## BGP Support

Enable BGP by adding a top-level `bgp` section. The `peers` list must reference existing `links` by **name**.

```yaml
bgp:
  asn: "<YOUR_ASN>"
  router_id: "<YOUR_ROUTER_ID>"   # typically the router's main loopback or link address
  # Optional: import route filters (prefix list)
  # import_filter:
  #   - "172.20.0.0/14"
  #   - "172.31.0.0/16"
  #   - "fd00::/8"
  peers:
    - name: "peer1"              # must match a link name
      address: "172.20.1.2"      # neighbor IP
      asn: 4242420002
      families: [ipv4-unicast, ipv6-unicast]   # also supports ipv4-labelled-unicast, ipv6-labelled-unicast
```

### Full DN42 Node Example

A realistic configuration combining static routes, WireGuard links, and BGP (including internal MPLS peer).

```yaml
bgp:
  asn: 4242420001
  router_id: "172.20.1.1"
  import_filter:
    - "172.20.0.0/14"
    - "172.31.0.0/16"
    - "fd00::/8"
  peers:
    - name: "peer1"
      address: "172.20.1.2"
      asn: 4242420002
      families: [ipv4-unicast, ipv6-unicast]
    - name: "internal"           # internal BGP + MPLS peer
      address: "172.20.2.2"
      asn: 4242420001
      families: [ipv4-unicast, ipv4-labelled-unicast]

routes:
  # route to be exported via BGP
  - prefix: "172.20.1.0/24"
    next_hop: "172.20.1.1"
    export: true
  # FIB-only route (not advertised)
  - prefix: "172.20.2.1/32"
    next_hop: "172.20.2.1"
    export: false

links:
  - name: "peer1"
    address: "172.20.1.1/32"
    peer_ip: "172.20.1.2"
    wireguard:
      listen_port: 51820
      private_key: "<base64-private-key>"
      mtu: 1420
      public_key: "<base64-public-key>"
      endpoint: "peer.example.com:51820"
      allowed_ips: "172.20.1.2/32"

  - name: "internal"
    address: "172.20.2.1/32"
    peer_ip: "172.20.2.2"
    wireguard:
      listen_port: 51821
      private_key: "<base64-private-key>"
      mtu: 1420
      public_key: "<base64-public-key>"
      endpoint: "internal.example.com:51821"
      allowed_ips: "172.20.2.2/32"

netstack:
  tcp_port: 8080
```

> **Note**: The `name` of a BGP peer **must** match the `name` of the corresponding WireGuard link.  
> `import_filter` restricts inbound BGP routes to the specified prefixes (if defined).
> 
> 
