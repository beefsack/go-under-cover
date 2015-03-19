package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
)

type WSSPlain struct {
	Address string
}

func NewWSSPlain(address string) *WSSPlain {
	return &WSSPlain{
		Address: address,
	}
}

func (wss *WSSPlain) Dial(network, address string) (io.ReadWriteCloser, error) {
	rawConn, err := tls.Dial("tcp", wss.Address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %v", err)
	}

	u, err := url.Parse(fmt.Sprintf("wss://%s/ws", wss.Address))
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address: %v", err)
	}
	query := url.Values{}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("failed to split address: %v", err)
	}
	query.Set("network", network)
	query.Set("host", host)
	query.Set("port", port)
	u.RawQuery = query.Encode()

	ws, _, err := websocket.NewClient(rawConn, u, http.Header{
		"Sec-Websocket-Protocol": {"chat"},
	}, 1024, 1024)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade to websocket: %v", err)
	}
	return ws.UnderlyingConn(), nil
}

func (wss *WSSPlain) Listen() error {
	return errors.New("not implemented")
}
