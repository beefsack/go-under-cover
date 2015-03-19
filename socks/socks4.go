package socks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/beefsack/go-under-cover/llog"
)

const (
	CDGranted            byte = 90
	CDRejectedOrFailed   byte = 91
	CDCannotConnectIdend byte = 92
	CDDifferentUserIds   byte = 93
)

type Socks4A struct{}

func (s4 *Socks4A) Negotiate(conn io.ReadWriter) (req *Request, err error) {
	req = &Request{
		Ver:      VerSocks4,
		ConnType: ConnTCP,
	}
	// Make request
	rep := CDGranted

	if err = s4.readVerOctet(conn); err != nil {
		return
	}

	if err = binary.Read(conn, ByteOrder, &req.Cmd); err != nil {
		err = fmt.Errorf("failed to read CMD octet: %v", err)
		return
	}
	if req.Cmd != CmdConnect {
		rep = CDRejectedOrFailed
	}

	if err = binary.Read(conn, ByteOrder, &req.DestPort); err != nil {
		err = fmt.Errorf("failed to read DST.PORT: %v", err)
	}

	addr := make([]byte, 4)
	if err = binary.Read(conn, ByteOrder, &addr); err != nil {
		err = fmt.Errorf("failed to read IPv4 DST.ADDR: %v", err)
		return
	}
	if req.DestAddr, err = DecodeIPv4(addr); err != nil {
		err = fmt.Errorf("failed to decode IPv4 DST.ADDR: %v", err)
		return
	}

	// User ID is null terminated
	if req.UserID, err = s4.readUntilNull(conn); err != nil {
		err = fmt.Errorf("failed to read USERID: %v", err)
		return
	}

	// Socks 4A: if we get a 0.0.0.X IP where X is non-zero, read null
	// terminated string and do DNS.
	llog.Trace("DestAddr we got was %s", req.DestAddr.String())
	if addr[0]+addr[1]+addr[2] == 0 && addr[3] != 0 {
		llog.Trace("got domain")
		var (
			domain []byte
		)
		if domain, err = s4.readUntilNull(conn); err != nil {
			err = fmt.Errorf("failed to read domain: %v", err)
			return
		}
		if req.DestAddr, err = DecodeDomain(domain); err != nil {
			err = fmt.Errorf("failed to decode domain: %v", err)
			return
		}
	}

	if rep != CDGranted {
		s4.SendResponseHeader(conn, req, &Response{
			Reply: rep,
		})
		err = fmt.Errorf("request failed with CD 0x%d", rep)
	}
	return
}

func (s4 *Socks4A) SendResponseHeader(
	conn io.ReadWriter,
	req *Request,
	res *Response,
) error {
	cd := res.Reply
	if cd == RepSucceeded {
		cd = CDGranted
	}
	destPort := res.BindPort
	if destPort == 0 {
		destPort = req.DestPort
	}
	addr := res.BindAddr
	if addr == nil {
		addr = req.DestAddr
	}
	ip, err := addr.ToIPv4()
	if err != nil {
		return fmt.Errorf("failed to convert %s to IPv4: %v", addr.String(), err)
	}
	reply := append([]byte{
		0x00, // This VER is the "reply version" and should be 0
		cd,
	})
	llog.Trace("Sending 0x%d", cd)
	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	if err := binary.Write(conn, ByteOrder, destPort); err != nil {
		return fmt.Errorf("failed to send DSTPORT: %v", err)
	}
	if _, err := conn.Write(ip.Encode()); err != nil {
		return fmt.Errorf("failed to send DSTIP: %v", err)
	}
	return nil
}

func (s4 *Socks4A) readVerOctet(conn io.ReadWriter) error {
	var ver byte
	if err := binary.Read(conn, ByteOrder, &ver); err != nil {
		return fmt.Errorf("failed to read client VER octet: %v", err)
	}
	if ver != VerSocks4 {
		return fmt.Errorf("incorrect VER, expected 0x04, received 0x%d", ver)
	}
	return nil
}

func (s4 *Socks4A) readUntilNull(conn io.ReadWriter) ([]byte, error) {
	b := bytes.NewBuffer([]byte{})
	for {
		p := make([]byte, 1)
		if _, err := conn.Read(p); err != nil {
			return b.Bytes(),
				fmt.Errorf("failed to read null terminated string: %v", err)
		}
		if p[0] == 0 {
			break
		}
		b.WriteByte(p[0])
	}
	return b.Bytes(), nil
}
