// Package norm contains functions to help normalize data.
package norm

import "strings"

// Email will normalize an email address.
func Email(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	addr, domain, ok := strings.Cut(s, "@")
	if !ok {
		return s
	}

	switch domain {
	case "gmail.com":
		addr = strings.ReplaceAll(addr, ".", "")
		addr = strings.Split(addr, "+")[0]
	}
	return addr + "@" + domain
}
