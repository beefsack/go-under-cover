package main

import (
	"fmt"
	"io"

	"github.com/beefsack/go-under-cover/bridge"
	"github.com/beefsack/go-under-cover/socks"
	"github.com/beefsack/go-under-cover/transport"
)

func socksHandler(trans transport.Transport) func(
	ver socks.Version,
	conn io.ReadWriter,
	req *socks.Request,
) error {
	return func(ver socks.Version, conn io.ReadWriter, req *socks.Request) error {
		network := "tcp"
		if req.ConnType == socks.ConnUDP {
			network = "udp"
		}
		dstConn, err := trans.Dial(
			network,
			fmt.Sprintf("%s:%d", req.DestAddr, req.DestPort),
		)
		if err != nil {
			return fmt.Errorf("failed to dial transport: %v", err)
		}
		defer dstConn.Close()
		if err := ver.SendResponseHeader(conn, req, &socks.Response{}); err != nil {
			return fmt.Errorf("failed to send response header: %v", err)
		}
		if err := bridge.Bridge(conn, dstConn); err != nil {
			return fmt.Errorf("failure during connection bridging: %v", err)
		}
		return nil
	}
}
