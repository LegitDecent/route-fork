package pool

import (
	"rofk/proxy"
	"sync"
)

type Pool struct {
	mu     sync.RWMutex
	valid  []*proxy.Proxy
	failed []*proxy.Proxy
	index  int
}

func New() *Pool { return &Pool{} }

func (p *Pool) AddValid(px *proxy.Proxy) {
	p.mu.Lock()
	p.valid = append(p.valid, px)
	p.mu.Unlock()
}

func (p *Pool) AddFailed(px *proxy.Proxy) {
	p.mu.Lock()
	p.failed = append(p.failed, px)
	p.mu.Unlock()
}

// Next returns the proxy at the current rotation index.
// wrap=true cycles back to 0 when exhausted; wrap=false returns nil.
func (p *Pool) Next(wrap bool) *proxy.Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.valid) == 0 {
		return nil
	}
	if p.index >= len(p.valid) {
		if !wrap {
			return nil
		}
		p.index = 0
	}
	px := p.valid[p.index]
	return px
}

func (p *Pool) Advance() {
	p.mu.Lock()
	p.index++
	p.mu.Unlock()
}

func (p *Pool) Valid() []*proxy.Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*proxy.Proxy, len(p.valid))
	copy(out, p.valid)
	return out
}

func (p *Pool) Failed() []*proxy.Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*proxy.Proxy, len(p.failed))
	copy(out, p.failed)
	return out
}

func (p *Pool) ValidCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.valid)
}

func (p *Pool) FailedCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.failed)
}

func (p *Pool) ClearValid() {
	p.mu.Lock()
	p.valid = p.valid[:0]
	p.index = 0
	p.mu.Unlock()
}

func (p *Pool) ClearFailed() {
	p.mu.Lock()
	p.failed = p.failed[:0]
	p.mu.Unlock()
}

func (p *Pool) ResetIndex() {
	p.mu.Lock()
	p.index = 0
	p.mu.Unlock()
}

// SetValid replaces the entire valid pool with the supplied slice and resets the index.
// Used after egress deduplication.
func (p *Pool) SetValid(proxies []*proxy.Proxy) {
	p.mu.Lock()
	p.valid = make([]*proxy.Proxy, len(proxies))
	copy(p.valid, proxies)
	p.index = 0
	p.mu.Unlock()
}
