package socks

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/beefsack/go-under-cover/llog"
)

const (
	VerSocks4 byte = 0x04
	VerSocks5 byte = 0x05

	ConnTCP byte = 0x00
	ConnUDP byte = 0x01

	CmdConnect      byte = 0x01
	CmdBind         byte = 0x02
	CmdUdpAddociate byte = 0x03

	ATypIPv4   byte = 0x01
	ATypDomain byte = 0x03
	ATypIPv6   byte = 0x04

	RepSucceeded                     byte = 0x00
	RepGeneralSocksServerFailure     byte = 0x01
	RepConnectionNotAllowedByRuleset byte = 0x02
	RepNetworkUnreachable            byte = 0x03
	RepHostUnreachable               byte = 0x04
	RepConnectionRefused             byte = 0x05
	RepTTLExpired                    byte = 0x06
	RepCommandNotSupported           byte = 0x07
	RepAddressTypeNotSupported       byte = 0x08
)

var ByteOrder = binary.BigEndian

type Request struct {
	Ver, ConnType, Cmd, Frag byte
	DestAddr                 Addr
	DestPort                 uint16
	UserID                   []byte
}

type Response struct {
	Reply    byte
	BindAddr Addr
	BindPort uint16
}

type Version interface {
	Negotiate(conn io.ReadWriter) (*Request, error)
	SendResponseHeader(conn io.ReadWriter, req *Request, res *Response) error
}

type readWriter struct {
	io.Reader
	io.Writer
}

type Socks45 struct{}

func FindVersion(ver byte) (v Version, ok bool) {
	ok = true
	switch ver {
	case VerSocks4:
		v = &Socks4A{}
	case VerSocks5:
		v = &Socks5{}
	default:
		ok = false
	}
	return
}

func (s45 *Socks45) Negotiate(conn io.ReadWriter) (*Request, error) {
	bufR := bufio.NewReader(conn)
	rw := readWriter{bufR, conn}
	v, err := bufR.Peek(1)
	if err != nil {
		return nil, fmt.Errorf("failed to get version byte: %v", err)
	}

	subVer, ok := FindVersion(v[0])
	if !ok {
		return nil, errors.New("could not find version")
	}
	return subVer.Negotiate(rw)
}

func (s45 *Socks45) SendResponseHeader(
	conn io.ReadWriter,
	req *Request,
	res *Response,
) error {
	subVer, ok := FindVersion(req.Ver)
	if !ok {
		return errors.New("could not find version")
	}
	return subVer.SendResponseHeader(conn, req, res)
}

func Listen(ver Version, listenAddr string, handler Handler) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			llog.Warn("failed to accept connection: %v", err)
		}
		go func() {
			defer conn.Close()
			llog.Debug("connection from %s", conn.RemoteAddr())
			req, err := ver.Negotiate(conn)
			if err != nil {
				llog.Warn("failed to negotiate: %v", err)
				return
			}
			if err := handler(ver, conn, req); err != nil {
				llog.Warn("failed to handle request: %v", err)
			}
		}()
	}
}
