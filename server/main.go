package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/beefsack/go-under-cover/bridge"
	"github.com/beefsack/go-under-cover/llog"
	"github.com/gorilla/websocket"
	"github.com/manveru/faker"
)

const (
	DefaultPrivFile = "key.pem"
	DefaultCertFile = "cert.pem"
)

var fak *faker.Faker

func init() {
	var err error
	fak, err = faker.New("en")
	if err != nil {
		log.Fatalf("failed to create faker: %v", err)
	}
}

func genKey() (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	file, err := os.OpenFile(
		DefaultPrivFile,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", DefaultPrivFile, err)
	}
	if err := pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		return nil, fmt.Errorf("failed to write %s: %v", DefaultPrivFile, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("failed to close %s: %v", DefaultPrivFile, err)
	}
	return priv, nil
}

func genCert(priv *rsa.PrivateKey) error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate a serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{fak.CompanyName()},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(7300 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	file, err := os.OpenFile(
		DefaultCertFile,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", DefaultCertFile, err)
	}
	if err := pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}); err != nil {
		return fmt.Errorf("failed to write %s: %v", DefaultCertFile, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %v", DefaultCertFile, err)
	}
	return nil
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func main() {
	var (
		listenAddr string
		logLevel   int
	)
	flag.StringVar(&listenAddr, "listen", ":1443", "the local address to listen on")
	flag.IntVar(&logLevel, "v", llog.LevelInfo, "the level to log, 1-5")
	flag.Parse()
	llog.Default.Level = logLevel

	_, privErr := os.Stat(DefaultPrivFile)
	_, certErr := os.Stat(DefaultCertFile)
	if os.IsNotExist(privErr) && os.IsNotExist(certErr) {
		priv, err := genKey()
		if err != nil {
			llog.Fatal("failed generating private key: %v", err)
		}
		if err := genCert(priv); err != nil {
			llog.Fatal("failed generating certificate: %v", err)
		}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("fart"))
	})
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		llog.Debug("WS /ws %s", r.RemoteAddr)
		values := r.URL.Query()
		host := values.Get("host")
		port := values.Get("port")
		if host == "" || port == "" {
			return
		}

		ws, err := upgrader.Upgrade(w, r, http.Header{
			"Sec-Websocket-Protocol": {"chat"},
		})
		defer ws.Close()
		if err != nil {
			llog.Warn("failed upgrading connection to websocket: %v", err)
			return
		}
		conn := ws.UnderlyingConn()

		target, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			return
		}
		defer target.Close()

		bridge.Bridge(conn, target)
	})

	llog.Info("listening on %s", listenAddr)
	if err := http.ListenAndServeTLS(
		listenAddr,
		DefaultCertFile,
		DefaultPrivFile,
		nil,
	); err != nil {
		llog.Fatal("failed to start server: %v", err)
	}
}
