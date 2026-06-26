package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"gouter/internal/netstack"
	"gouter/internal/router"
	"gouter/internal/wg"

	"golang.zx2c4.com/wireguard/device"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	gouterSK := os.Getenv("GOUTER_SK")
	kernelPK := os.Getenv("KERNEL_PK")
	listenPort := os.Getenv("LISTEN_PORT")
	gouterIP := os.Getenv("GOUTER_IP")
	kernelIP := os.Getenv("KERNEL_IP")

	if gouterSK == "" || kernelPK == "" || listenPort == "" || gouterIP == "" || kernelIP == "" {
		log.Fatal("env: GOUTER_SK KERNEL_PK LISTEN_PORT GOUTER_IP KERNEL_IP required")
	}

	gouterSKHex, err := b64ToHex(gouterSK)
	if err != nil {
		log.Fatalf("bad GOUTER_SK: %v", err)
	}
	kernelPKHex, err := b64ToHex(kernelPK)
	if err != nil {
		log.Fatalf("bad KERNEL_PK: %v", err)
	}

	gouterPrefix, err := netip.ParsePrefix(gouterIP)
	if err != nil {
		log.Fatalf("bad GOUTER_IP: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ns := netstack.NewManager()
	fib := router.NewFIB()
	nexthop := router.NewNexthopResolver(fib)
	r := router.NewRouter(fib, nexthop, ns, nil)

	t := wg.NewTransport("wg-gouter", 1420, device.LogLevelVerbose)
	uapiCfg := fmt.Sprintf(`private_key=%s
listen_port=%s
replace_peers=true
public_key=%s
endpoint=127.0.0.1:51821
replace_allowed_ips=true
allowed_ip=%s
`, gouterSKHex, listenPort, kernelPKHex, kernelIP+"/32")

	if err := t.Configure(uapiCfg); err != nil {
		log.Printf("wg configure warning: %v", err)
	}

	_, err = ns.AddNIC(netstack.NICConfig{
		Name:    "wg-gouter",
		Address: gouterPrefix,
		MTU:     1420,
	})
	if err != nil {
		log.Fatalf("add nic: %v", err)
	}
	nexthop.AddTransport("wg-gouter", []netip.Prefix{gouterPrefix})

	if err := t.Up(); err != nil {
		log.Fatalf("wg up: %v", err)
	}
	r.AddTransport(t)

	go handleOutbound(ctx, ns, "wg-gouter", t)

	log.Printf("gouter: IP=%s, listen=:%s, peer=%s/32", gouterIP, listenPort, kernelIP)

	r.Run(ctx)
	log.Printf("shutting down...")
	t.Close()
}

func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func handleOutbound(ctx context.Context, ns *netstack.Manager, name string, t *wg.Transport) {
	ch := ns.GetNICOutChannel(ctx, name)
	if ch == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			if err := t.Write(pkt); err != nil {
				log.Printf("outbound: %v", err)
			}
		}
	}
}
