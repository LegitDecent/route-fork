package pool

import (
	"testing"

	"rofk/proxy"
)

func makeProxy(host string, port int) *proxy.Proxy {
	return &proxy.Proxy{Host: host, Port: port, Proto: "socks5"}
}

// ── Next / Advance ────────────────────────────────────────────────────────────

func TestNextEmptyPool(t *testing.T) {
	p := New()
	if got := p.Next(true); got != nil {
		t.Errorf("Next on empty pool = %v, want nil", got)
	}
	if got := p.Next(false); got != nil {
		t.Errorf("Next(false) on empty pool = %v, want nil", got)
	}
}

func TestNextReturnsCurrent(t *testing.T) {
	p := New()
	px := makeProxy("1.2.3.4", 1080)
	p.AddValid(px)
	got := p.Next(false)
	if got != px {
		t.Errorf("Next() returned wrong proxy")
	}
}

func TestNextDoesNotAdvance(t *testing.T) {
	p := New()
	p.AddValid(makeProxy("1.1.1.1", 1080))
	p.AddValid(makeProxy("2.2.2.2", 1080))
	// Calling Next twice without Advance should return the same proxy
	a := p.Next(false)
	b := p.Next(false)
	if a != b {
		t.Errorf("Next without Advance returned different proxies")
	}
}

func TestAdvanceRotates(t *testing.T) {
	p := New()
	px1 := makeProxy("1.1.1.1", 1080)
	px2 := makeProxy("2.2.2.2", 1080)
	p.AddValid(px1)
	p.AddValid(px2)

	first := p.Next(false)
	p.Advance()
	second := p.Next(false)

	if first == second {
		t.Error("Advance did not rotate to next proxy")
	}
	if second != px2 {
		t.Errorf("after Advance: got %v, want px2", second)
	}
}

func TestNextWrapTrue(t *testing.T) {
	p := New()
	p.AddValid(makeProxy("1.1.1.1", 1080))
	// Advance past the end
	p.Advance()
	p.Advance()
	// With wrap=true should wrap back to index 0
	got := p.Next(true)
	if got == nil {
		t.Error("Next(wrap=true) after exhaustion returned nil, want proxy")
	}
}

func TestNextWrapFalse(t *testing.T) {
	p := New()
	p.AddValid(makeProxy("1.1.1.1", 1080))
	p.Advance()
	// Index now past end, wrap=false
	got := p.Next(false)
	if got != nil {
		t.Errorf("Next(wrap=false) after exhaustion = %v, want nil", got)
	}
}

// ── Counts ────────────────────────────────────────────────────────────────────

func TestValidCount(t *testing.T) {
	p := New()
	if p.ValidCount() != 0 {
		t.Errorf("fresh pool ValidCount = %d, want 0", p.ValidCount())
	}
	p.AddValid(makeProxy("1.1.1.1", 1080))
	p.AddValid(makeProxy("2.2.2.2", 1080))
	if p.ValidCount() != 2 {
		t.Errorf("ValidCount = %d, want 2", p.ValidCount())
	}
}

func TestFailedCount(t *testing.T) {
	p := New()
	p.AddFailed(makeProxy("1.1.1.1", 1080))
	if p.FailedCount() != 1 {
		t.Errorf("FailedCount = %d, want 1", p.FailedCount())
	}
}

// ── Valid / Failed snapshots ──────────────────────────────────────────────────

func TestValidReturnsCopy(t *testing.T) {
	p := New()
	px := makeProxy("1.1.1.1", 1080)
	p.AddValid(px)
	snap := p.Valid()
	if len(snap) != 1 {
		t.Fatalf("Valid() len = %d, want 1", len(snap))
	}
	// Mutating the snapshot should not affect the pool
	snap[0] = makeProxy("9.9.9.9", 9999)
	if p.Valid()[0] == snap[0] {
		t.Error("Valid() returned a reference, not a copy")
	}
}

func TestFailedReturnsCopy(t *testing.T) {
	p := New()
	px := makeProxy("1.1.1.1", 1080)
	p.AddFailed(px)
	snap := p.Failed()
	if len(snap) != 1 {
		t.Fatalf("Failed() len = %d, want 1", len(snap))
	}
	snap[0] = makeProxy("9.9.9.9", 9999)
	if p.Failed()[0] == snap[0] {
		t.Error("Failed() returned a reference, not a copy")
	}
}

// ── Clear / Reset ─────────────────────────────────────────────────────────────

func TestClearValid(t *testing.T) {
	p := New()
	p.AddValid(makeProxy("1.1.1.1", 1080))
	p.AddValid(makeProxy("2.2.2.2", 1080))
	p.Advance()
	p.ClearValid()
	if p.ValidCount() != 0 {
		t.Errorf("after ClearValid: count = %d, want 0", p.ValidCount())
	}
	// index should also reset
	if p.Next(false) != nil {
		t.Error("after ClearValid: Next should return nil")
	}
}

func TestClearFailed(t *testing.T) {
	p := New()
	p.AddFailed(makeProxy("1.1.1.1", 1080))
	p.ClearFailed()
	if p.FailedCount() != 0 {
		t.Errorf("after ClearFailed: count = %d, want 0", p.FailedCount())
	}
}

func TestResetIndex(t *testing.T) {
	p := New()
	p.AddValid(makeProxy("1.1.1.1", 1080))
	p.AddValid(makeProxy("2.2.2.2", 1080))
	p.Advance()
	p.Advance()
	p.ResetIndex()
	// After reset, Next should return the first proxy again
	got := p.Next(false)
	if got == nil {
		t.Error("after ResetIndex: Next returned nil")
	}
}
