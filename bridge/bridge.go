package bridge

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/beefsack/go-under-cover/llog"
)

func Bridge(c1, c2 net.Conn) {
	bridgeStr := fmt.Sprintf("%s <-> %s", c1.RemoteAddr(), c2.RemoteAddr())
	llog.Trace("%s : bridging", bridgeStr)
	quit := make(chan struct{}, 2)
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		ConnCopy(c1, c2, quit)
		quit <- struct{}{}
		wg.Done()
	}()
	go func() {
		ConnCopy(c2, c1, quit)
		quit <- struct{}{}
		wg.Done()
	}()
	wg.Wait()
	llog.Trace("%s : finished", bridgeStr)
}

func ConnCopy(dst, src net.Conn, quit chan struct{}) error {
	copyStr := fmt.Sprintf("%s <- %s", dst.RemoteAddr(), src.RemoteAddr())
	llog.Trace("%s : starting", copyStr)
	for {
		select {
		case <-quit:
			llog.Trace("%s : quitting", copyStr)
			return nil
		default:
		}
		dl := time.Now().Add(time.Second)
		src.SetDeadline(dl)
		dst.SetDeadline(dl)
		_, err := io.Copy(dst, src)
		netErr, ok := err.(net.Error)
		if err == nil || !ok || !netErr.Timeout() {
			llog.Debug("%s : ended with error %v", copyStr, err)
			return err
		}
	}
}
