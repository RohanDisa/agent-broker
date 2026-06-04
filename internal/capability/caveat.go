package capability

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CaveatType is a macaroon-style restriction. Caveats only add limits.
type CaveatType string

const (
	CaveatTool        CaveatType = "tool"
	CaveatOperation   CaveatType = "operation"
	CaveatResource    CaveatType = "resource"
	CaveatTask        CaveatType = "task"
	CaveatNonce       CaveatType = "nonce"
	CaveatExpires     CaveatType = "expires"
	CaveatSingleUse   CaveatType = "single_use"
	CaveatMaxCalls    CaveatType = "max_calls"
	CaveatDestination CaveatType = "destination"
	CaveatGrant       CaveatType = "grant"
)

// Caveat is one attenuation predicate encoded in the credential.
type Caveat struct {
	Type  CaveatType `json:"type"`
	Value string     `json:"value"`
}

func (c Caveat) String() string {
	return string(c.Type) + "=" + c.Value
}

// Canonical serializes a caveat for hashing. Field order is fixed.
func (c Caveat) Canonical() string {
	return string(c.Type) + ":" + c.Value
}

// CaveatChainHash is the macaroon-style chained hash of identifier + caveats.
// Stripping or reordering a caveat changes the head, so the Ed25519 signature
// over the head no longer verifies.
func CaveatChainHash(identifier string, caveats []Caveat) []byte {
	h := sha256.Sum256([]byte(identifier))
	cur := h[:]
	for _, c := range caveats {
		next := sha256.Sum256(append(append([]byte{}, cur...), []byte(c.Canonical())...))
		cur = next[:]
	}
	return cur
}

func ChainHeadHex(identifier string, caveats []Caveat) string {
	return hex.EncodeToString(CaveatChainHash(identifier, caveats))
}

// Attenuate appends caveats that are strictly tighter. Widening is rejected
// before any signing happens.
func Attenuate(existing []Caveat, extra []Caveat) ([]Caveat, error) {
	out := append([]Caveat{}, existing...)
	for _, e := range extra {
		if err := checkNarrower(existing, e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func checkNarrower(existing []Caveat, extra Caveat) error {
	for _, e := range existing {
		if e.Type != extra.Type {
			continue
		}
		switch extra.Type {
		case CaveatResource:
			if !IsNarrowerOrEqual(extra.Value, e.Value) {
				return fmt.Errorf("%w: resource caveat %q widens %q", ErrWidening, extra.Value, e.Value)
			}
		case CaveatTool, CaveatOperation, CaveatTask, CaveatGrant, CaveatNonce:
			if extra.Value != e.Value {
				return fmt.Errorf("%w: cannot change %s from %q to %q", ErrWidening, extra.Type, e.Value, extra.Value)
			}
		case CaveatExpires:
			expNew, err1 := time.Parse(time.RFC3339, extra.Value)
			expOld, err2 := time.Parse(time.RFC3339, e.Value)
			if err1 != nil || err2 != nil {
				return fmt.Errorf("%w: bad expires caveat", ErrWidening)
			}
			if expNew.After(expOld) {
				return fmt.Errorf("%w: expires caveat extends ttl", ErrWidening)
			}
		case CaveatMaxCalls:
			n, err1 := strconv.Atoi(extra.Value)
			o, err2 := strconv.Atoi(e.Value)
			if err1 != nil || err2 != nil || n > o {
				return fmt.Errorf("%w: max_calls caveat %s widens %s", ErrWidening, extra.Value, e.Value)
			}
		case CaveatDestination:
			if extra.Value != e.Value && !IsNarrowerOrEqual(extra.Value, e.Value) && !MatchHostPattern(e.Value, extra.Value) {
				return fmt.Errorf("%w: destination caveat %q widens %q", ErrWidening, extra.Value, e.Value)
			}
		}
	}
	return nil
}

func GrantCaveats(g Grant, tool, operation, resource, nonce string, expires time.Time) []Caveat {
	cs := []Caveat{
		{Type: CaveatGrant, Value: g.ID},
		{Type: CaveatTask, Value: g.TaskID},
		{Type: CaveatTool, Value: tool},
		{Type: CaveatOperation, Value: operation},
		{Type: CaveatResource, Value: resource},
		{Type: CaveatNonce, Value: nonce},
		{Type: CaveatSingleUse, Value: "true"},
		{Type: CaveatExpires, Value: expires.UTC().Format(time.RFC3339)},
	}
	if g.Constraints.MaxCalls > 0 {
		cs = append(cs, Caveat{Type: CaveatMaxCalls, Value: strconv.Itoa(g.Constraints.MaxCalls)})
	}
	if len(g.Constraints.DestinationAllowlist) > 0 {
		cs = append(cs, Caveat{Type: CaveatDestination, Value: strings.Join(g.Constraints.DestinationAllowlist, ",")})
	}
	return cs
}
