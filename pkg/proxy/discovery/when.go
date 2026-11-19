package discovery

import (
	"fmt"
	"strings"
)

// The `when` guard language is deliberately tiny: comparisons of a known fact
// against a quoted literal, joined by && or ||. It is not an expression
// evaluator and must never grow into one — collection logic belongs in the
// pack's commands, and anything richer becomes a sandbox-escape surface in a
// binary that runs signed content as root-adjacent users.
//
//	os_family == "rhel"
//	os_family == "debian" || os_family == "suse"
//	os_family == "rhel" && os_major != "7"

type whenExpr struct {
	or [][]comparison // outer slice = OR terms, inner = AND terms
}

type comparison struct {
	fact  string
	op    string // == or !=
	value string
}

// knownFacts are the only facts a guard may reference. Restricting the
// vocabulary means a typo in a pack fails loudly at load time instead of
// silently skipping every host.
var knownFacts = map[string]bool{
	"os_family": true, // rhel, debian, suse, alpine
	"os_id":     true, // ubuntu, centos, rocky, sles, ...
	"os_major":  true, // major version, e.g. "9"
	"arch":      true, // x86_64, aarch64
}

func parseWhen(s string) (*whenExpr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty when expression")
	}

	expr := &whenExpr{}
	for _, orPart := range strings.Split(s, "||") {
		var ands []comparison
		for _, andPart := range strings.Split(orPart, "&&") {
			c, err := parseComparison(andPart)
			if err != nil {
				return nil, err
			}
			ands = append(ands, c)
		}
		expr.or = append(expr.or, ands)
	}
	return expr, nil
}

func parseComparison(s string) (comparison, error) {
	s = strings.TrimSpace(s)

	var op string
	switch {
	case strings.Contains(s, "=="):
		op = "=="
	case strings.Contains(s, "!="):
		op = "!="
	default:
		return comparison{}, fmt.Errorf("when expression %q: expected == or !=", s)
	}

	parts := strings.SplitN(s, op, 2)
	fact := strings.TrimSpace(parts[0])
	rawVal := strings.TrimSpace(parts[1])

	if !knownFacts[fact] {
		return comparison{}, fmt.Errorf("when expression references unknown fact %q", fact)
	}

	value, err := unquote(rawVal)
	if err != nil {
		return comparison{}, fmt.Errorf("when expression %q: %w", s, err)
	}

	return comparison{fact: fact, op: op, value: value}, nil
}

func unquote(s string) (string, error) {
	if len(s) < 2 {
		return "", fmt.Errorf("value must be quoted")
	}
	first, last := s[0], s[len(s)-1]
	if (first != '"' && first != '\'') || first != last {
		return "", fmt.Errorf("value must be quoted")
	}
	inner := s[1 : len(s)-1]
	if strings.ContainsAny(inner, `"'`) {
		return "", fmt.Errorf("value contains a quote character")
	}
	return inner, nil
}

// eval reports whether the guard matches the probed facts. A guard that
// references a fact we could not probe returns an error rather than false:
// "we don't know" and "does not apply" are different outcomes, and only the
// latter should silently skip a collector.
func (e *whenExpr) eval(facts map[string]string) (bool, error) {
	for _, ands := range e.or {
		all := true
		for _, c := range ands {
			got, ok := facts[c.fact]
			if !ok {
				return false, fmt.Errorf("fact %q not available for this host", c.fact)
			}
			var match bool
			switch c.op {
			case "==":
				match = got == c.value
			case "!=":
				match = got != c.value
			}
			if !match {
				all = false
				break
			}
		}
		if all {
			return true, nil
		}
	}
	return false, nil
}
