package tools

import "sync"

type Payments struct {
	mu      sync.Mutex
	charges []string
}

func NewPayments() *Payments { return &Payments{} }

func (p *Payments) Name() string { return "payments" }

func (p *Payments) Exec(req Request) Result {
	if req.Operation != "charge" {
		return Result{Error: "payments: unknown operation"}
	}
	amt := arg(req.Arguments, "amount")
	p.mu.Lock()
	p.charges = append(p.charges, req.Resource+"="+amt)
	n := len(p.charges)
	p.mu.Unlock()
	return inheritOut(req, "tool", req.Resource, "charged "+amt+" on "+req.Resource+" (#"+itoa(n)+")", true)
}

func (p *Payments) Charges() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.charges))
	copy(out, p.charges)
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
