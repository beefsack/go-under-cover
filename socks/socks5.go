package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Socks5 struct{}

func (s5 *Socks5) Negotiate(conn io.ReadWriter) (req *Request, err error) {
	req = &Request{
		Ver:      VerSocks5,
		ConnType: ConnTCP,
	}
	// Negotiate method
	var (
		nMethods      byte
		clientMethods []byte
	)

	rep := RepSucceeded

	if err = s5.readVerOctet(conn); err != nil {
		return
	}

	if err = binary.Read(conn, ByteOrder, &nMethods); err != nil {
		err = fmt.Errorf("failed to read NMETHODS octet: %v", err)
		return
	}

	clientMethods = make([]byte, nMethods)
	if err = binary.Read(conn, ByteOrder, &clientMethods); err != nil {
		err = fmt.Errorf("failed to read METHODS octets: %v", err)
		return
	}
	found := false
	for _, m := range clientMethods {
		if m == 0x00 {
			found = true
			break
		}
	}
	if !found {
		conn.Write([]byte{0xFF})
		err = errors.New("only x00 NO AUTHENTICATION REQUIRED is supported")
		return
	}
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		err = fmt.Errorf("failed to write method octets: %v", err)
		return
	}

	// Make request
	var rsv byte

	if err = s5.readVerOctet(conn); err != nil {
		return
	}

	if err = binary.Read(conn, ByteOrder, &req.Cmd); err != nil {
		err = fmt.Errorf("failed to read CMD octet: %v", err)
		return
	}
	if req.Cmd != CmdConnect {
		rep = RepCommandNotSupported
	}

	if err = binary.Read(conn, ByteOrder, &rsv); err != nil {
		err = fmt.Errorf("failed to read RSV octet: %v", err)
		return
	}

	if err = binary.Read(conn, ByteOrder, &req.AddrType); err != nil {
		err = fmt.Errorf("failed to read ATYP octet: %v", err)
		return
	}

	switch req.AddrType {
	case ATypIPv4:
		addr := make([]byte, 4)
		if err := binary.Read(conn, ByteOrder, &addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 DST.ADDR: %v", err)
		}
		parts := make([]string, 4)
		for i, b := range addr {
			parts[i] = strconv.Itoa(int(b))
		}
		req.DestAddr = strings.Join(parts, ".")
		req.RawDestAddr = addr
	case ATypDomain:
		var domainLen byte
		if err := binary.Read(conn, ByteOrder, &domainLen); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %v", err)
		}
		domain := make([]byte, domainLen)
		if err := binary.Read(conn, ByteOrder, &domain); err != nil {
			return nil, fmt.Errorf("failed to read domain: %v", err)
		}
		req.DestAddr = string(domain)
		req.RawDestAddr = append([]byte{domainLen}, domain...)
	case ATypIPv6:
		addr := make([]byte, 16)
		if err := binary.Read(conn, ByteOrder, &addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 DST.ADDR: %v", err)
		}
		parts := make([]string, 8)
		for i := 0; i < 8; i++ {
			parts[i] = fmt.Sprintf("%X", addr[i*2:i*2+1])
		}
		req.DestAddr = strings.Join(parts, ":")
		req.RawDestAddr = addr
	default:
		rep = RepAddressTypeNotSupported
	}

	if err = binary.Read(conn, ByteOrder, &req.DestPort); err != nil {
		err = fmt.Errorf("failed to read DST.PORT: %v", err)
	} else if rep != RepSucceeded {
		s5.SendResponseHeader(conn, req, &Response{
			Reply: rep,
		})
		err = fmt.Errorf("request failed with REP 0x%d", rep)
	}
	return
}

func (s5 *Socks5) SendResponseHeader(
	conn io.ReadWriter,
	req *Request,
	res *Response,
) error {
	addrType := res.AddrType
	if addrType == 0x00 {
		addrType = req.AddrType
	}
	bindAddr := res.BindAddr
	if bindAddr == nil {
		bindAddr = req.RawDestAddr
	}
	bindPort := res.BindPort
	if bindPort == 0 {
		bindPort = req.DestPort
	}
	reply := append([]byte{
		VerSocks5,
		res.Reply,
		0x00, // RSV
		addrType,
	}, bindAddr...)
	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	if err := binary.Write(conn, ByteOrder, bindPort); err != nil {
		return fmt.Errorf("failed to send bind port: %v", err)
	}
	return nil
}

func (s5 *Socks5) readVerOctet(conn io.ReadWriter) error {
	var ver byte
	if err := binary.Read(conn, ByteOrder, &ver); err != nil {
		return fmt.Errorf("failed to read client VER octet: %v", err)
	}
	if ver != 0x05 {
		return fmt.Errorf("only SOCKS5 is supported, received 0x%d", ver)
	}
	return nil
}
