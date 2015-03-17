package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

const (
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

func handleConn(conn net.Conn, proxyAddr string) error {
	defer conn.Close()
	dstConn, err := negotiate(conn, proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to negotiate: %v", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		io.Copy(dstConn, conn)
		wg.Done()
	}()
	go func() {
		io.Copy(conn, dstConn)
		wg.Done()
	}()
	wg.Wait()

	return nil
}

func negotiate(conn net.Conn, proxyAddr string) (net.Conn, error) {
	// Negotiate method
	var (
		nMethods      byte
		clientMethods []byte
	)

	rep := RepSucceeded

	if err := readVerOctet(conn); err != nil {
		return nil, err
	}

	if err := binary.Read(conn, ByteOrder, &nMethods); err != nil {
		return nil, fmt.Errorf("failed to read NMETHODS octet: %v", err)
	}

	clientMethods = make([]byte, nMethods)
	if err := binary.Read(conn, ByteOrder, &clientMethods); err != nil {
		return nil, fmt.Errorf("failed to read METHODS octets: %v", err)
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
		return nil, errors.New("only x00 NO AUTHENTICATION REQUIRED is supported")
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return nil, fmt.Errorf("failed to write method octets: %v", err)
	}

	// Make request
	var (
		cmd, rsv, aTyp byte
		dstAddr        string
		dstPort        uint16
	)

	if err := readVerOctet(conn); err != nil {
		return nil, err
	}

	if err := binary.Read(conn, ByteOrder, &cmd); err != nil {
		return nil, fmt.Errorf("failed to read CMD octet: %v", err)
	}
	if cmd != CmdConnect {
		rep = RepCommandNotSupported
	}

	if err := binary.Read(conn, ByteOrder, &rsv); err != nil {
		return nil, fmt.Errorf("failed to read RSV octet: %v", err)
	}

	if err := binary.Read(conn, ByteOrder, &aTyp); err != nil {
		return nil, fmt.Errorf("failed to read ATYP octet: %v", err)

	}
	rawAddr := []byte{}
	switch aTyp {
	case ATypIPv4:
		addr := make([]byte, 4)
		if err := binary.Read(conn, ByteOrder, &addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 DST.ADDR: %v", err)
		}
		parts := make([]string, 4)
		for i, b := range addr {
			parts[i] = strconv.Itoa(int(b))
		}
		dstAddr = strings.Join(parts, ".")
		rawAddr = addr
	case ATypDomain:
		var domainLen byte
		if err := binary.Read(conn, ByteOrder, &domainLen); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %v", err)
		}
		domain := make([]byte, domainLen)
		if err := binary.Read(conn, ByteOrder, &domain); err != nil {
			return nil, fmt.Errorf("failed to read domain: %v", err)
		}
		dstAddr = string(domain)
		rawAddr = append([]byte{domainLen}, domain...)
	case ATypIPv6:
		addr := make([]byte, 16)
		if err := binary.Read(conn, ByteOrder, &addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 DST.ADDR: %v", err)
		}
		parts := make([]string, 8)
		for i := 0; i < 8; i++ {
			parts[i] = fmt.Sprintf("%X", addr[i*2:i*2+1])
		}
		dstAddr = strings.Join(parts, ":")
		rawAddr = addr
	default:
		rep = RepAddressTypeNotSupported
	}

	if err := binary.Read(conn, ByteOrder, &dstPort); err != nil {
		return nil, fmt.Errorf("failed to read DST.PORT: %v", err)
	}

	rawConn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Fatalf("failed to connect to server: %v", err)
	}

	u, err := url.Parse(fmt.Sprintf("wss://%s/ws", proxyAddr))
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address: %v", err)
	}
	query := url.Values{}
	query.Set("host", dstAddr)
	query.Set("port", strconv.Itoa(int(dstPort)))
	u.RawQuery = query.Encode()

	ws, _, err := websocket.NewClient(rawConn, u, http.Header{
		"Sec-Websocket-Protocol": {"chat"},
	}, 1024, 1024)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade to websocket: %v", err)
	}
	dstConn := ws.UnderlyingConn()

	reply := append([]byte{
		0x05, // SOCKS5
		rep,
		0x00, // RSV
		aTyp,
	}, rawAddr...)
	if _, err := conn.Write(reply); err != nil {
		return nil, fmt.Errorf("failed to send reply: %v", err)
	}
	if err := binary.Write(conn, ByteOrder, dstPort); err != nil {
		return nil, fmt.Errorf("failed to send reply port: %v", err)
	}

	if rep != RepSucceeded {
		return nil, fmt.Errorf("request failed with REP 0x%d", rep)
	}
	return dstConn, nil
}

func readVerOctet(conn net.Conn) error {
	var ver byte
	if err := binary.Read(conn, ByteOrder, &ver); err != nil {
		return fmt.Errorf("failed to read client VER octet: %v", err)
	}
	if ver != 0x05 {
		return fmt.Errorf("only SOCKS5 is supported, received 0x%d", ver)
	}
	return nil
}

func main() {
	var listenAddr string
	flag.StringVar(&listenAddr, "listen", ":1080", "the local address to listen on")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		log.Fatalf("you must specify the server address to proxy to")
	}
	proxyAddr := args[0]
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to create listener: %v", err)
	}
	log.Printf("listening on %s", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
		}
		go func() {
			addr := conn.RemoteAddr()
			if err := handleConn(conn, proxyAddr); err != nil {
				log.Printf("%s: %v", addr, err)
			}
		}()
	}

}
