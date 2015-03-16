package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

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
	_, privErr := os.Stat(DefaultPrivFile)
	_, certErr := os.Stat(DefaultCertFile)
	if os.IsNotExist(privErr) && os.IsNotExist(certErr) {
		priv, err := genKey()
		if err != nil {
			log.Fatalf("failed generating private key: %v", err)
		}
		if err := genCert(priv); err != nil {
			log.Fatalf("failed generating certificate: %v", err)
		}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("fart"))
	})
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()
		host := values.Get("host")
		port := values.Get("port")
		if host == "" || port == "" {
			return
		}
		log.Printf("Got connection for %s:%s", host, port)

		ws, err := upgrader.Upgrade(w, r, http.Header{
			"Sec-Websocket-Protocol": {"chat"},
		})
		if err != nil {
			log.Printf("Error upgrading connection to websocket: %v", err)
			return
		}
		log.Printf("Upgraded for %s:%s", host, port)
		conn := ws.UnderlyingConn()

		target, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			conn.Close()
			return
		}
		log.Printf("Connected to %s:%s", host, port)

		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			log.Printf("Writing to %s:%s", host, port)
			io.Copy(target, conn)
			log.Printf("Writing to %s:%s finished", host, port)
			wg.Done()
		}()
		go func() {
			log.Printf("Reading from %s:%s", host, port)
			io.Copy(conn, target)
			log.Printf("Reading from %s:%s", host, port)
			wg.Done()
		}()
		wg.Wait()
		log.Printf("%s:%s finished", host, port)
	})

	if err := http.ListenAndServeTLS(
		":1443",
		DefaultCertFile,
		DefaultPrivFile,
		nil,
	); err != nil {
		log.Panicf("failed to start server: %v", err)
	}
}
