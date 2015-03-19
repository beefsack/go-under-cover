package main

import (
	"flag"

	"github.com/beefsack/go-under-cover/llog"
	"github.com/beefsack/go-under-cover/socks"
	"github.com/beefsack/go-under-cover/transport"
)

func main() {
	var (
		listenAddr string
		logLevel   int
	)
	flag.StringVar(&listenAddr, "listen", ":1080", "the local address to listen on")
	flag.IntVar(&logLevel, "v", llog.LevelInfo, "the level to log, 1-5")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		llog.Fatal("you must specify the server address to proxy to")
	}
	llog.Default.Level = logLevel
	trans := transport.NewWSSPlain(args[0])

	llog.Info("listening on %s", listenAddr)
	if err := socks.Listen(
		&socks.Socks45{},
		listenAddr,
		socksHandler(trans),
	); err != nil {
		llog.Fatal("failed to listen: %s", err)
	}
}
