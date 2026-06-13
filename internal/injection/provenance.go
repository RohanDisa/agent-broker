package injection

import "strings"

// Source is a trust label. User is the operator. Tool is an authorized
// result. Web and Doc are untrusted external content — the injection vector.
type Source string

const (
	User Source = "user"
	Tool Source = "tool"
	Web  Source = "web"
	Doc  Source = "doc"
)

// Rank is higher for less trusted sources. Taint takes the max (worst) label.
func (s Source) Rank() int {
	switch s {
	case User:
		return 0
	case Tool:
		return 1
	case Doc:
		return 2
	case Web:
		return 3
	default:
		return 3
	}
}

func Worst(a, b Source) Source {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
}

// Provenance tags one piece of content and the chain it flowed through.
type Provenance struct {
	Source     Source   `json:"source"`
	Origin     string   `json:"origin,omitempty"`
	TaintChain []Source `json:"taint_chain,omitempty"`
}

func (p Provenance) Effective() Source {
	w := p.Source
	for _, s := range p.TaintChain {
		w = Worst(w, s)
	}
	if w == "" {
		return User
	}
	return w
}

func (p Provenance) Inherit(child Source, origin string) Provenance {
	chain := append([]Source{}, p.TaintChain...)
	chain = append(chain, p.Source)
	return Provenance{
		Source:     Worst(p.Effective(), child),
		Origin:     origin,
		TaintChain: chain,
	}
}

func ParseSource(s string) Source {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "user":
		return User
	case "tool":
		return Tool
	case "web":
		return Web
	case "doc":
		return Doc
	default:
		return Web
	}
}

// Tagged is content plus its label. Mock tools persist this so intermediate
// writes cannot drop taint (scenario 9, provenance laundering).
type Tagged struct {
	Body       string     `json:"body"`
	Provenance Provenance `json:"provenance"`
	Sensitive  bool       `json:"sensitive"`
}

func Join(tags ...Tagged) Tagged {
	out := Tagged{}
	var b strings.Builder
	for i, t := range tags {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(t.Body)
		out.Provenance.Source = Worst(out.Provenance.Effective(), t.Provenance.Effective())
		out.Provenance.TaintChain = append(out.Provenance.TaintChain, t.Provenance.Effective())
		if t.Sensitive {
			out.Sensitive = true
		}
		if t.Provenance.Origin != "" && out.Provenance.Origin == "" {
			out.Provenance.Origin = t.Provenance.Origin
		}
	}
	out.Body = b.String()
	return out
}
