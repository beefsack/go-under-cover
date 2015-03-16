package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/websocket"
)

func main() {
	rawConn, err := tls.Dial("tcp", "localhost:1443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Panicf("failed to connect to server: %v", err)
	}

	u, err := url.Parse("wss://localhost:1443/ws?host=google.com&port=80")
	if err != nil {
		log.Panicf("failed to parse url: %v", err)
	}

	ws, _, err := websocket.NewClient(rawConn, u, http.Header{
		"Sec-Websocket-Protocol": {"chat"},
	}, 1024, 1024)
	if err != nil {
		log.Panicf("failed to upgrade to websocket: %v", err)
	}
	conn := ws.UnderlyingConn()

	req, err := http.NewRequest("GET", "http://google.com", nil)
	if err != nil {
		log.Panicf("failed to create request: %v", err)
	}
	if err := req.Write(conn); err != nil {
		log.Panicf("failed to send request: %v", err)
	}
	log.Print("sent request")

	io.Copy(os.Stdout, conn)

	ws.Close()
}
