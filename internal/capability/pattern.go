package capability

import (
	"strings"
)

// MatchPattern reports whether value is authorized by pattern.
//
// Syntax:
//   - exact string match
//   - '*' matches a single path segment (no '/')
//   - trailing '/*' matches any descendant under that prefix (including the prefix)
//   - '**' matches across '/'
//
// email://*@ourco.com matches email://alice@ourco.com but not email://alice@evil.com.
func MatchPattern(pattern, value string) bool {
	if pattern == value || pattern == "*" || pattern == "**" {
		return true
	}
	if pattern == "" {
		return value == ""
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if value == prefix || strings.HasPrefix(value, prefix+"/") {
			return true
		}
	}
	return globMatch(pattern, value)
}

// MatchHostPattern matches allowlist entries like "*@ourco.com" or "alice@ourco.com"
// against a bare address or a resource URI (email://alice@ourco.com).
func MatchHostPattern(pattern, dest string) bool {
	dest = stripScheme(dest)
	pattern = stripScheme(pattern)
	if pattern == dest || pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*@") {
		return strings.HasSuffix(dest, pattern[1:])
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(dest, pattern[1:]) || dest == strings.TrimPrefix(pattern, "*.")
	}
	return globMatch(pattern, dest)
}

func stripScheme(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}

// IsNarrowerOrEqual reports whether requested is an attenuation of granted
// (equal or strictly more specific). This is one-directional.
func IsNarrowerOrEqual(requested, granted string) bool {
	if granted == requested || granted == "*" || granted == "**" {
		return true
	}
	if !hasWildcard(requested) {
		return MatchPattern(granted, requested)
	}
	// Both are patterns. Requested may only add restriction.
	if strings.HasSuffix(granted, "/*") {
		gprefix := strings.TrimSuffix(granted, "/*")
		r := requested
		if strings.HasSuffix(r, "/*") {
			r = strings.TrimSuffix(r, "/*")
		}
		if r == gprefix || strings.HasPrefix(r, gprefix+"/") {
			return true
		}
	}
	if !hasWildcard(granted) {
		return false
	}
	// Conservative: requested pattern must match as a value of granted, after
	// treating requested wildcards as a representative concrete token.
	probe := strings.NewReplacer("**", "probe", "*", "probe").Replace(requested)
	return MatchPattern(granted, probe) && moreSpecific(requested, granted)
}

func moreSpecific(requested, granted string) bool {
	if strings.Count(requested, "*") < strings.Count(granted, "*") {
		return true
	}
	if len(requested) > len(granted) && strings.HasPrefix(strings.TrimSuffix(requested, "/*"), strings.TrimSuffix(granted, "/*")) {
		return true
	}
	return requested != granted && MatchPattern(granted, strings.ReplaceAll(requested, "*", "x"))
}

func hasWildcard(s string) bool {
	return strings.Contains(s, "*")
}

func globMatch(pattern, value string) bool {
	return globRec(pattern, value)
}

func globRec(pattern, value string) bool {
	for {
		if pattern == "" {
			return value == ""
		}
		if strings.HasPrefix(pattern, "**") {
			rest := strings.TrimPrefix(pattern, "**")
			rest = strings.TrimPrefix(rest, "/")
			if rest == "" {
				return true
			}
			if globRec(rest, value) {
				return true
			}
			for i := 0; i < len(value); i++ {
				if value[i] == '/' && globRec(rest, value[i+1:]) {
					return true
				}
				if globRec(rest, value[i:]) {
					return true
				}
			}
			return false
		}
		if pattern[0] == '*' {
			rest := pattern[1:]
			if rest == "" {
				return !strings.Contains(value, "/")
			}
			if rest[0] != '*' {
				for i := 0; i <= len(value); i++ {
					if i < len(value) && value[i] == '/' {
						break
					}
					if globRec(rest, value[i:]) {
						return true
					}
				}
				return false
			}
		}
		if value == "" {
			return false
		}
		if pattern[0] != value[0] {
			return false
		}
		pattern = pattern[1:]
		value = value[1:]
	}
}
