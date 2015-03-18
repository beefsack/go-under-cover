package bridge

import (
	"io"

	"github.com/beefsack/go-under-cover/llog"
)

func Bridge(rw1, rw2 io.ReadWriter) error {
	var err error
	quit := make(chan struct{}, 1)
	go func() {
		_, err = io.Copy(rw1, rw2)
		quit <- struct{}{}
	}()
	go func() {
		_, err = io.Copy(rw2, rw1)
		quit <- struct{}{}
	}()
	llog.Trace("waiting for quit")
	<-quit
	llog.Trace("quit")
	return err
}
