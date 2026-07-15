package internal

import (
	"fmt"
	"net"
	"strings"
)

type Whitelist struct {
	nets []*net.IPNet
}

func NewWhitelist(value string) (*Whitelist, error) {
	w := &Whitelist{}

	if strings.TrimSpace(value) == "" {
		return w, nil
	}

	for _, rawItem := range strings.Split(value, ",") {
		item := strings.TrimSpace(rawItem)
		if item == "" {
			continue
		}

		if strings.Contains(item, "/") {
			ip, network, err := net.ParseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("invalid IPv4 network %q", item)
			}
			if ip.To4() == nil {
				return nil, fmt.Errorf("unsupported address family %q", item)
			}

			network.IP = ip.To4()
			w.nets = append(w.nets, network)
			continue
		}

		ip := net.ParseIP(item)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address %q", item)
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("unsupported address family %q", item)
		}

		_, network, err := net.ParseCIDR(ip.To4().String() + "/32")
		if err != nil {
			return nil, fmt.Errorf("invalid IPv4 address %q", item)
		}
		w.nets = append(w.nets, network)
	}

	return w, nil
}

func (w *Whitelist) Contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}

	ip = ip.To4()
	for _, network := range w.nets {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (w *Whitelist) Len() int {
	return len(w.nets)
}
