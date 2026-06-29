package internal

import (
	"fmt"
	"net"
	"strings"
)

type Whitelist struct { nets []*net.IPNet }

func NewWhitelist(value string) (*Whitelist, error) {
	w := &Whitelist{}
	if strings.TrimSpace(value) == "" { return w, nil }
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" { continue }
		if !strings.Contains(item, "/") { item += "/32" }
		_, n, err := net.ParseCIDR(item)
		if err != nil { return nil, fmt.Errorf("bad whitelist item %q: %w", item, err) }
		w.nets = append(w.nets, n)
	}
	return w, nil
}

func (w *Whitelist) Contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, n := range w.nets { if n.Contains(ip) { return true } }
	return false
}
func (w *Whitelist) Len() int { return len(w.nets) }
