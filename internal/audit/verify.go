package audit

import "fmt"

// BrokenLink names the first entry whose hash or predecessor pointer is wrong.
type BrokenLink struct {
	Seq    int    `json:"seq"`
	Reason string `json:"reason"`
	Want   string `json:"want,omitempty"`
	Got    string `json:"got,omitempty"`
}

func (b BrokenLink) Error() string {
	return fmt.Sprintf("audit chain broken at seq %d: %s", b.Seq, b.Reason)
}

// Verify walks the chain and reports the first broken link.
func Verify(entries []Entry) error {
	prev := GenesisHash
	for i, e := range entries {
		if e.Seq != i+1 {
			return BrokenLink{Seq: e.Seq, Reason: "sequence gap"}
		}
		if e.PrevHash != prev {
			return BrokenLink{Seq: e.Seq, Reason: "prev_hash does not match previous entry", Want: prev, Got: e.PrevHash}
		}
		want := HashEntry(e)
		if e.Hash != want {
			return BrokenLink{Seq: e.Seq, Reason: "entry hash does not match contents (tamper)", Want: want, Got: e.Hash}
		}
		prev = e.Hash
	}
	return nil
}

func (l *Log) Verify() error {
	return Verify(l.Entries())
}
