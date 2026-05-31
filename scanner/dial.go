package scanner

import (
	"context"
	"net"
	"time"

	"rofk/proxy"
)

// DialThroughProxyCtx is the default DialFunc: it opens a SOCKS tunnel to
// host:port through p, but returns immediately if ctx is cancelled instead of
// blocking until the dial timeout. The underlying dial goroutine finishes on
// its own timeout and self-closes any late connection; it holds no locks, so
// leaking it briefly is harmless.
//
// It is pure SOCKS - there is no direct-connection fallback - so a scan driven
// by this dialer always egresses through the proxy or fails.
func DialThroughProxyCtx(ctx context.Context, p *proxy.Proxy, host string, port int, to time.Duration) (net.Conn, error) {
	type res struct {
		c net.Conn
		e error
	}
	ch := make(chan res, 1)
	go func() {
		c, e := proxy.DialThroughProxy(p, host, port, to)
		ch <- res{c, e}
	}()
	select {
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	case r := <-ch:
		return r.c, r.e
	}
}
