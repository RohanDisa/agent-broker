package capability

import "errors"

var (
	ErrWidening       = errors.New("attenuation refuses widening")
	ErrBadSignature   = errors.New("credential signature invalid")
	ErrExpired        = errors.New("credential expired")
	ErrReplay         = errors.New("credential nonce already used")
	ErrCaveatBroken   = errors.New("credential caveat not satisfied")
	ErrChainMismatch  = errors.New("caveat chain hash mismatch")
	ErrNoGrant        = errors.New("no matching grant")
	ErrRevoked        = errors.New("grant revoked")
	ErrMalformed      = errors.New("credential malformed")
	ErrNonceCollision = errors.New("nonce already registered")
)
