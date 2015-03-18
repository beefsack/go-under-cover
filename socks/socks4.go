package socks

import (
	"errors"
	"io"
)

type Socks4 struct{}

func (s4 *Socks4) Negotiate(conn io.ReadWriter) (*Request, error) {
	return nil, errors.New("Socks 4 not implemented")
}

func (s4 *Socks4) SendResponseHeader(
	conn io.ReadWriter,
	req *Request,
	res *Response,
) error {
	return errors.New("Socks 4 not implemented")
}
