# gouter

完全用户态的 SD-WAN / DN42 路由节点。WireGuard 隧道 + BGP 路由 + SR-MPLS 标签转发，不依赖内核 tun/tap/netlink。

## 架构

```
                  控制面                        数据面

DN42 peers ──kernel WG──→ gobgp (内核 TCP)       MPLS/UDP transport
    │                        │                       │
    │                iBGP / eBGP session              │
    │                    over proxy                   │
    │                        │                       │
Internal A ──US WG──→ TCP proxy ──→ gobgp            │
Internal B ──US WG──→ TCP proxy ──→ gobgp            │
    │                        │                       │
    │                  best-path watch                │
    │                        │                       │
    │              ┌─────────┴─────────┐              │
    │              │                   │              │
    │             FIB                LFIB            │
    │              │                   │              │
    └──────────────┼───────────────────┼──────────────┘
                   │     Router        │
                   │  Event Loop       │
                   │                   │
              ┌────┴────┐        ┌────┴────┐
              │ WG fwd  │        │MPLS PUSH│
              │         │        │SWAP/POP │
              └────┬────┘        └────┬────┘
                   │                  │
              netstack            MPLS/UDP
              (本地 TCP)          transport
```

## 组件

| 组件 | 包 | 职责 |
|------|------|------|
| **Router** | `internal/router` | 主事件循环：收到包 → 查 FIB/LFIB → 转发或本地交付 |
| **FIB** | `internal/router/fib.go` | IP 路由表，最长前缀匹配，BGP 动态填充 |
| **LFIB** | `internal/mpls/lfib.go` | MPLS 标签转发表，inLabel → POP/SWAP/PUSH |
| **WireGuard Transport** | `internal/wg` | 用户态 WG 隧道（wireguard-go + channel-based tun） |
| **MPLS/UDP Transport** | `internal/mpls/transport.go` | MPLS 帧通过 UDP 收发 |
| **BGP Speaker** | `internal/bgp/speaker.go` | gobgp v4 封装，eBGP/iBGP/BGP-LU |
| **BGP Proxy** | `internal/bgp/proxy.go` | TCP 代理：内核 TCP ↔ 用户态 netstack 双向桥接 |
| **BGP Filter** | `internal/bgp/filter.go` | 可选 import prefix filter（`import_filter` 配置） |
| **Netstack** | `internal/netstack` | gVisor 用户态 TCP/IP 栈，gonet 适配 |
| **Config** | `internal/config` | YAML 配置解析 |

## 配置

```yaml
bgp:
  asn: 4242420001
  router_id: "172.20.1.1"
  peers:
    - name: "dn42-peer-a"
      address: "10.0.1.2"           # peer 的 WG IP
      asn: 4242420002                # eBGP: 不同 AS
      peer_bgp_port: 179
      families: [ipv4-unicast, ipv6-unicast, ipv4-labelled-unicast]
    - name: "internal-1"
      address: "10.0.2.2"
      asn: 4242420001                # iBGP: 同 AS
      families: [ipv4-unicast, ipv4-labelled-unicast]
  local_routes:
    - prefix: "10.99.0.0/24"
      next_hop: "10.0.1.1"
      label: true                    # 通过 BGP-LU 通告

wireguard:
  - name: "wg-a"
    listen_port: 51820
    private_key: "<base64>"          # wg genkey 输出
    address: "10.0.1.1/24"           # 格式: IP/prefix
    mtu: 1420
    peers:
      - public_key: "<base64>"       # wg pubkey 输出
        endpoint: "1.2.3.4:51820"
        allowed_ips: "10.0.1.2/32"

mpls:                                 # 可选
  udp:
    listen_port: 16635
    peers: ["1.2.3.4:16635"]         # MPLS peer 的 IP:port

netstack:
  tcp_port: 8080                     # 本地 TCP 监听端口
```

### BGP Family 字符串

| 配置值 | 含义 | AFI/SAFI |
|--------|------|----------|
| `ipv4-unicast` | IPv4 单播 | 1/1 |
| `ipv6-unicast` | IPv6 单播 | 2/1 |
| `ipv4-labelled-unicast` | BGP-LU (MPLS label) | 1/4 |
| `ipv6-labelled-unicast` | BGP-LU v6 | 2/4 |

## BGP 代理机制

gobgp 使用内核 TCP，但 peer 在用户态 WG 里，内核够不到。TCP 代理解决：

```
出站（gobgp → peer）:
  gobgp → 127.0.0.X:1100Y (proxy 内核 TCP listener)
    proxy → netstack.DialTCP(peer_WG_IP:179)
      用户态 WG → peer

入站（peer → gobgp）:
  peer → 用户态 WG → netstack :179
    proxy → net.Dialer{LocalAddr: 127.0.0.X}.Dial("127.0.0.1:179")
      gobgp 看到源 IP 127.0.0.X → 匹配 neighbor 配置
```

每个 peer 自动分配：
- 唯一 loopback IP（127.0.0.2 起）
- 唯一 outbound 端口（11001 起）
- gobgp 自动配置 `neighbor 127.0.0.X port 1100Y`

代理是纯 TCP 双向 `io.Copy`，不解析 BGP 协议。

## MPLS 操作

### LFIB

| 操作 | 含义 | 输入标签 → 输出 |
|------|------|-----------------|
| POP | 弹出标签，露出内层包 | label L → 内层 IP 或 MPLS |
| SWAP | 替换标签 | label L → label L' |
| PUSH | 压入标签栈 | label L → labels L1+L2+... |
| PHP | 倒数第二跳弹出 | label 3 → 无标签 IP 包 |

### 数据流

```
MPLS/UDP Transport:
  收: [UDP][MPLS label][内层] → LFIB lookup → POP/SWAP/PUSH

POP 后内层是 IP:
  → FIB lookup → WG 转发 / netstack 本地交付

POP 后内层是 MPLS:
  → 递归 LFIB lookup（双层标签处理）

FIB ActionPush:
  IP 包 → PUSH MPLS label(s) → 转发至 MPLS/UDP Transport
```

## DN42 接入

### 路由过滤

可选 `import_filter` 限制接收的前缀，不设则接受全部：

```yaml
bgp:
  import_filter:
    - "172.20.0.0/14"    # 只接受 DN42 地址空间
    - "fd00::/8"
```

### 准备工作

1. 生成 WG 密钥：`wg genkey | tee sk | wg pubkey > pk`
2. 申请 DN42 ASN 和 IP 分配
3. 找 peer 交换 WG 公钥、endpoint、ASN
4. 编写 `config.yaml`

### 运行

```bash
go build -o gouter .
./gouter config.yaml
```

### DN42 典型配置

```yaml
bgp:
  asn: 4242420001
  router_id: "172.20.1.1"
  peers:
    - name: "dn42-peer"
      address: "10.0.0.2"
      asn: 4242420002
      families: [ipv4-unicast, ipv6-unicast]
  local_routes:
    - prefix: "172.20.1.0/24"
      next_hop: "10.0.0.1"

wireguard:
  - name: "wg-dn42"
    listen_port: 51820
    private_key: "<your-sk>"
    address: "10.0.0.1/32"
    peers:
      - public_key: "<peer-pk>"
        endpoint: "peer.example.com:51820"
        allowed_ips: "10.0.0.2/32"
```

## 构建

```bash
# 依赖
go mod tidy

# 构建
go build -o gouter .

# 测试
go test ./internal/...

# 单独测试
go test -v ./internal/mpls/
go test -v ./internal/router/
go test -v ./internal/wg/
go test -v ./internal/bgp/
go test -v ./internal/config/

# 验证
go vet ./...
```

## 依赖

| 库 | 用途 |
|------|------|
| `golang.zx2c4.com/wireguard` | WG 隧道 |
| `gvisor.dev/gvisor` | 用户态 TCP/IP 栈 |
| `github.com/osrg/gobgp/v4` | BGP 协议 |
| `gopkg.in/yaml.v3` | 配置解析 |

## 设计原则

- **零 root**：不依赖 netlink、TUN/TAP、raw socket
- **全用户态**：WG + TCP/IP + MPLS 全在进程内
- **不 fork**：gobgp 不改源码，通过 TCP 代理桥接
- **协议无感知代理**：BGP 代理是纯 TCP 双向转发，不解析 BGP
