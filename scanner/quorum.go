package scanner

// QuorumVerdict is the outcome of a per-port quorum scan: the conclusion drawn
// after some number of proxies have independently voted on whether a port is open.
type QuorumVerdict int

const (
	// QuorumUnreachable means no proxy could reach the target at all (every
	// attempt was a proxy-side error). The port's true state is unknown - most
	// likely filtered.
	QuorumUnreachable QuorumVerdict = iota
	// QuorumOpen means at least `quorum` distinct proxies agreed the port is open
	// and no proxy authoritatively refused it.
	QuorumOpen
	// QuorumRefuted means a proxy got an authoritative "connection refused" from
	// the target. This overrides any open votes - an honest refusal beats a
	// lying proxy's fake success - so the port is reported closed.
	QuorumRefuted
	// QuorumUnconfirmed means one or more proxies connected (voted open) but the
	// quorum was not reached and no proxy refuted it. Treated as closed/filtered
	// to avoid trusting a single (possibly lying) proxy.
	QuorumUnconfirmed
)

// DecideQuorum reduces a port's vote tally to a single verdict.
//
//   - refuted takes precedence over everything: an authoritative "connection
//     refused" from any proxy means the port is closed, even if other (lying)
//     proxies claimed it open.
//   - otherwise, reaching the quorum of agreeing proxies means open.
//   - a non-zero but sub-quorum count is unconfirmed (treated as closed).
//   - zero successful connections means no proxy could reach the target.
//
// confirmations is the number of distinct proxies that connected successfully;
// quorum is how many must agree; refuted is whether any proxy reported an
// authoritative target-side refusal.
func DecideQuorum(confirmations, quorum int, refuted bool) QuorumVerdict {
	switch {
	case refuted:
		return QuorumRefuted
	case confirmations >= quorum:
		return QuorumOpen
	case confirmations > 0:
		return QuorumUnconfirmed
	default:
		return QuorumUnreachable
	}
}

// IsOpen reports whether the verdict means the port should be recorded as open.
func (v QuorumVerdict) IsOpen() bool { return v == QuorumOpen }
