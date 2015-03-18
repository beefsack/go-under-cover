package socks

import (
	"errors"
	"io"
)

type Handler func(ver Version, conn io.ReadWriter, req *Request) error

func BridgeHandler(ver Version, conn io.ReadWriter, req *Request) error {
	return errors.New("not implemented")
}
