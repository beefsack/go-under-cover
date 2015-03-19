package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	var (
		rsv, addrType byte
	)

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

	if err = binary.Read(conn, ByteOrder, &addrType); err != nil {
		err = fmt.Errorf("failed to read ATYP octet: %v", err)
		return
	}

	switch addrType {
	case ATypIPv4:
		addr := make([]byte, 4)
		if err = binary.Read(conn, ByteOrder, &addr); err != nil {
			err = fmt.Errorf("failed to read IPv4 DST.ADDR: %v", err)
			return
		}
		if req.DestAddr, err = DecodeIPv4(addr); err != nil {
			err = fmt.Errorf("failed to parse IPv4 DST.ADDR: %v", err)
			return
		}
	case ATypDomain:
		var domainLen byte
		if err = binary.Read(conn, ByteOrder, &domainLen); err != nil {
			err = fmt.Errorf("failed to read domain length for DST.ADDR: %v", err)
			return
		}
		domain := make([]byte, domainLen)
		if err = binary.Read(conn, ByteOrder, &domain); err != nil {
			err = fmt.Errorf("failed to read domain DST.ADDR: %v", err)
			return
		}
		if req.DestAddr, err = DecodeDomain(domain); err != nil {
			err = fmt.Errorf("failed to parse domain DST.ADDR: %v", err)
			return
		}
	case ATypIPv6:
		addr := make([]byte, 16)
		if err = binary.Read(conn, ByteOrder, &addr); err != nil {
			err = fmt.Errorf("failed to read IPv4 DST.ADDR: %v", err)
		}
		if req.DestAddr, err = DecodeIPv6(addr); err != nil {
			err = fmt.Errorf("failed to parse IPv6 DST.ADDR: %v", err)
			return
		}
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
	bindAddr := res.BindAddr
	if bindAddr == nil {
		bindAddr = req.DestAddr
	}
	var encoded []byte
	switch bindAddr.Type() {
	case ATypDomain:
		raw := bindAddr.Encode()
		encoded = append([]byte{byte(len(raw))}, raw...)
	default:
		encoded = bindAddr.Encode()
	}
	bindPort := res.BindPort
	if bindPort == 0 {
		bindPort = req.DestPort
	}
	reply := append([]byte{
		VerSocks5,
		res.Reply,
		0x00, // RSV
		bindAddr.Type(),
	}, encoded...)
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
	if ver != VerSocks5 {
		return fmt.Errorf("incorrect VER, expected 0x04, received 0x%d", ver)
	}
	return nil
}
