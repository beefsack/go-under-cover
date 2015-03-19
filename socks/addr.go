package socks

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Addr interface {
	Type() byte
	Encode() []byte
	ToIPv4() (AddrIPv4, error)
	String() string
}

func Decode(typ byte, in []byte) (Addr, error) {
	switch typ {
	case ATypIPv4:
		return DecodeIPv4(in)
	case ATypIPv6:
		return DecodeIPv6(in)
	case ATypDomain:
		return DecodeDomain(in)
	default:
		return nil, fmt.Errorf("unknown address type 0x%d", typ)
	}
	return nil, nil
}

func DecodeIPv4(in []byte) (addr AddrIPv4, err error) {
	if len(in) != 4 {
		err = errors.New("expected input to be 4 bytes long")
		return
	}
	addr = AddrIPv4{}
	copy(addr[:], in)
	return
}

func DecodeIPv6(in []byte) (addr AddrIPv6, err error) {
	if len(in) != 16 {
		err = errors.New("expected input to be 16 bytes long")
		return
	}
	addr = AddrIPv6{}
	copy(addr[:], in)
	return addr, nil
}

func DecodeDomain(in []byte) (addr AddrDomain, err error) {
	addr = in
	return
}

type AddrIPv4 [4]byte

func ParseIPv4(input string) (addr AddrIPv4, err error) {
	parts := strings.Split(input, ".")
	if len(parts) != 4 {
		err = fmt.Errorf("expected to have 4 dot separated parts in %s", input)
		return
	}
	addr = AddrIPv4{}
	for index, p := range parts {
		var i int
		if i, err = strconv.Atoi(p); err != nil || i < 0 || i > 255 {
			err = fmt.Errorf("part %d in %s not a byte", index, input)
			return
		}
		addr[index] = byte(i)
	}
	return
}

func (addr AddrIPv4) Type() byte {
	return ATypIPv4
}

func (addr AddrIPv4) Encode() []byte {
	return addr[:]
}

func (addr AddrIPv4) ToIPv4() (AddrIPv4, error) {
	return addr, nil
}

func (addr AddrIPv4) String() string {
	parts := make([]string, 4)
	for i, b := range addr {
		parts[i] = strconv.Itoa(int(b))
	}
	return strings.Join(parts, ".")
}

type AddrIPv6 [16]byte

func (addr AddrIPv6) Type() byte {
	return ATypIPv6
}

func (addr AddrIPv6) Encode() []byte {
	return addr[:]
}

func (addr AddrIPv6) ToIPv4() (AddrIPv4, error) {
	return DecodeIPv4(addr[2:5])
}

func (addr AddrIPv6) String() string {
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = fmt.Sprintf("%x", addr[i*2:i*2+1])
	}
	return strings.Join(parts, ":")
}

type AddrDomain []byte

func (addr AddrDomain) Type() byte {
	return ATypDomain
}

func (addr AddrDomain) Encode() []byte {
	return addr
}

func (addr AddrDomain) ToIPv4() (AddrIPv4, error) {
	ip, err := net.ResolveIPAddr("ip4", string(addr))
	if err != nil {
		return AddrIPv4{}, fmt.Errorf(
			"failed to lookup %s: %v",
			string(addr),
			err,
		)
	}
	return ParseIPv4(ip.IP.String())
}

func (addr AddrDomain) String() string {
	return string(addr)
}
