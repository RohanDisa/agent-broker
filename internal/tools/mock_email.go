package tools

import "sync"

type sentMail struct {
	To   string
	Body string
}

type Email struct {
	mu   sync.Mutex
	sent []sentMail
}

func NewEmail() *Email { return &Email{} }

func (e *Email) Name() string { return "email" }

func (e *Email) Exec(req Request) Result {
	if req.Operation != "send" {
		return Result{Error: "email: unknown operation"}
	}
	to := arg(req.Arguments, "to")
	if to == "" {
		to = req.Resource
	}
	body := arg(req.Arguments, "body")
	e.mu.Lock()
	e.sent = append(e.sent, sentMail{To: to, Body: body})
	e.mu.Unlock()
	return inheritOut(req, "tool", "email://sent", "sent to "+to, false)
}

func (e *Email) Sent() []sentMail {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]sentMail, len(e.sent))
	copy(out, e.sent)
	return out
}
