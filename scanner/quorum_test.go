package scanner

import "testing"

func TestDecideQuorum(t *testing.T) {
	cases := []struct {
		name          string
		confirmations int
		quorum        int
		refuted       bool
		want          QuorumVerdict
	}{
		// open: enough proxies agreed, nobody refused
		{"quorum met exactly", 2, 2, false, QuorumOpen},
		{"quorum exceeded", 3, 2, false, QuorumOpen},
		{"quorum 1 single vote", 1, 1, false, QuorumOpen},

		// refuted always wins - even if the quorum was reached, an honest
		// "connection refused" beats lying proxies' open votes.
		{"refuted overrides met quorum", 3, 2, true, QuorumRefuted},
		{"refuted with no votes", 0, 2, true, QuorumRefuted},
		{"refuted with one vote", 1, 2, true, QuorumRefuted},

		// unconfirmed: some agreed but below quorum, nobody refused
		{"one vote short of quorum", 1, 2, false, QuorumUnconfirmed},
		{"two short of quorum-3", 1, 3, false, QuorumUnconfirmed},

		// unreachable: nobody connected
		{"no votes", 0, 2, false, QuorumUnreachable},
		{"no votes quorum-1", 0, 1, false, QuorumUnreachable},
	}
	for _, tc := range cases {
		got := DecideQuorum(tc.confirmations, tc.quorum, tc.refuted)
		if got != tc.want {
			t.Errorf("%s: DecideQuorum(%d, %d, %v) = %v, want %v",
				tc.name, tc.confirmations, tc.quorum, tc.refuted, got, tc.want)
		}
	}
}

func TestQuorumVerdictIsOpen(t *testing.T) {
	if !QuorumOpen.IsOpen() {
		t.Error("QuorumOpen.IsOpen() = false, want true")
	}
	for _, v := range []QuorumVerdict{QuorumUnreachable, QuorumRefuted, QuorumUnconfirmed} {
		if v.IsOpen() {
			t.Errorf("%v.IsOpen() = true, want false", v)
		}
	}
}
