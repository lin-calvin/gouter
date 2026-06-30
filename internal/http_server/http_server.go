package http_server

import (
	"fmt"
	"gouter/internal/appctx"
	"net/http"
	"os"
	"runtime"

	"github.com/common-nighthawk/go-figure"
)

func CreateHttpServer(ac *appctx.AppContext) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		banner := figure.NewFigure("Gouter", "isometric1", true)
		fmt.Fprint(w, banner.String())
		fmt.Fprintf(w, "----------------------------------------------\n")
		hostname, _ := os.Hostname()
		fmt.Fprintf(w, "Host: %s\n", hostname)
		fmt.Fprintf(w, "Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		if ac.Config.BGP.ASN > 0 {
			fmt.Fprintf(w, "ASN: %d\n", ac.Config.BGP.ASN)
		}
		fmt.Fprintf(w, "Routes: %d\n", len(ac.FIB.List()))
	})
	mux.HandleFunc("/routes", func(w http.ResponseWriter, r *http.Request) {
		routes := ac.FIB.List()
		fmt.Fprintf(w, "fib: %d routes:", len(routes))
		for _, r := range routes {
			fmt.Fprintf(w, "  %s via %s [%s]\n", r.Prefix, r.NextHop, r.Transport)
		}

	})
	return mux
}
