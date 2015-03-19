package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/beefsack/go-under-cover/bridge"
	"github.com/beefsack/go-under-cover/llog"
	"github.com/beefsack/go-under-cover/socks"
	"github.com/gorilla/websocket"
)

func wsHandler(proxyAddr string) func(
	ver socks.Version,
	conn io.ReadWriter,
	req *socks.Request,
) error {
	return func(ver socks.Version, conn io.ReadWriter, req *socks.Request) error {
		rawConn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return fmt.Errorf("failed to connect to server: %v", err)
		}
		defer rawConn.Close()

		u, err := url.Parse(fmt.Sprintf("wss://%s/ws", proxyAddr))
		if err != nil {
			return fmt.Errorf("invalid proxy address: %v", err)
		}
		query := url.Values{}
		query.Set("host", req.DestAddr.String())
		query.Set("port", strconv.Itoa(int(req.DestPort)))
		u.RawQuery = query.Encode()

		ws, _, err := websocket.NewClient(rawConn, u, http.Header{
			"Sec-Websocket-Protocol": {"chat"},
		}, 1024, 1024)
		if err != nil {
			return fmt.Errorf("failed to upgrade to websocket: %v", err)
		}
		dstConn := ws.UnderlyingConn()

		if err := ver.SendResponseHeader(conn, req, &socks.Response{}); err != nil {
			return fmt.Errorf("failed to send response header: %v", err)
		}

		return bridge.Bridge(conn, dstConn)
	}
}

func main() {
	var (
		listenAddr string
		logLevel   int
	)
	flag.StringVar(&listenAddr, "listen", ":1080", "the local address to listen on")
	flag.IntVar(&logLevel, "v", llog.LevelInfo, "the level to log, 1-5")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		llog.Fatal("you must specify the server address to proxy to")
	}
	llog.Default.Level = logLevel
	proxyAddr := args[0]

	llog.Info("listening on %s", listenAddr)
	if err := socks.Listen(&socks.Socks45{}, listenAddr, wsHandler(proxyAddr)); err != nil {
		llog.Fatal("failed to listen: %s", err)
	}
}
