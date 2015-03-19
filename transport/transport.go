package transport

import "io"

type Transport interface {
	Dial(network, address string) (io.ReadWriteCloser, error)
	Listen() error
}
