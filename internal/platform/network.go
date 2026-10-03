package platform

import (
	"context"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Interface is one network interface.
type Interface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
	MAC   string   `json:"mac,omitempty"`
	Up    bool     `json:"up"`
	Kind  string   `json:"kind"` // loopback | lan | vpn | virtual | container | unknown
	Scope string   `json:"scope"`
}

// Socket is one listening or bound socket.
type Socket struct {
	Proto    string               `json:"proto"`
	Addr     string               `json:"addr"`
	Port     int                  `json:"port"`
	Scope    models.ExposureScope `json:"scope"`
	Process  string               `json:"process,omitempty"`
	PID      int                  `json:"pid,omitempty"`
	Wildcard bool                 `json:"wildcard"`
}

// Network returns the host's interfaces and listening sockets plus the
// capability levels observed.
//
// The four elements are always returned even when they are empty, because an
// empty list and "could not enumerate" are different facts and the report has
// to be able to tell them apart.
func Network(ctx context.Context, e *Env) ([]Interface, []Socket, []models.SupportLevel) {
	ifaces, lvl1 := interfaces(ctx, e)
	socks, lvl2 := listeningSockets(ctx, e)
	return ifaces, socks, []models.SupportLevel{lvl1, lvl2}
}

// netInterfaces uses the Go standard library. It is the only source that works
// identically on all four platforms, which makes it the fallback everywhere
// except Windows, where it reports interfaces without bind scope.
func netInterfaces() []Interface {
	names, err := interfaceNames()
	if err != nil {
		return nil
	}
	out := make([]Interface, 0, len(names))
	for _, n := range names {
		iface := Interface{Name: n}
		iface.Addrs = interfaceAddrs(n)
		iface.Up = interfaceUp(n)
		iface.MAC = interfaceMAC(n)
		iface.Kind, iface.Scope = classifyInterface(n, iface.Addrs)
		out = append(out, iface)
	}
	return out
}

// classifyInterface turns an interface name and address set into an exposure
// class. The name is the strongest signal available without extra privileges,
// because the convention that loopback devices are named lo/lo0 and tunnel
// devices are named tun/tap/wg holds on every platform Amina supports.
func classifyInterface(name string, addrs []string) (string, string) {
	l := strings.ToLower(name)
	for _, a := range addrs {
		if a == "127.0.0.1" || a == "::1" {
			return "loopback", string(models.ScopeLoopback)
		}
	}
	switch {
	case l == "lo" || l == "lo0" || strings.HasPrefix(l, "loopback"):
		return "loopback", string(models.ScopeLoopback)
	case strings.HasPrefix(l, "wg"), strings.HasPrefix(l, "tun"), strings.HasPrefix(l, "tap"),
		strings.Contains(l, "vpn"), strings.Contains(l, "utun"), strings.HasPrefix(l, "ppp"):
		return "vpn", string(models.ScopeVPN)
	case strings.HasPrefix(l, "docker"), strings.HasPrefix(l, "br-"), strings.HasPrefix(l, "veth"),
		strings.HasPrefix(l, "virbr"), strings.HasPrefix(l, "cni"), strings.HasPrefix(l, "flannel"),
		strings.HasPrefix(l, "podman"), strings.HasPrefix(l, "kube"):
		return "container", string(models.ScopeContainer)
	case strings.HasPrefix(l, "vmnet"), strings.HasPrefix(l, "vboxnet"), strings.HasPrefix(l, "vnic"),
		strings.HasPrefix(l, "hyper-v"), strings.HasPrefix(l, "vEthernet"):
		return "virtual", string(models.ScopeVirtual)
	}
	if len(addrs) > 0 {
		return "lan", string(models.ScopeLAN)
	}
	return "unknown", string(models.ScopeUnknown)
}

// classifyAddr determines the exposure scope of a bind address. This is the
// single most load-bearing classification in Amina's network module: the same
// service bound to 127.0.0.1 and to 0.0.0.0 is a completely different
// assessment, and conflating them is the "open port = vulnerability" error the
// framework forbids.
func classifyAddr(addr string) (models.ExposureScope, bool) {
	a := strings.ToLower(stripZone(strings.TrimSpace(addr)))
	switch a {
	case "", "0.0.0.0", "::", "[::]", "*":
		return models.ScopeWildcard, true
	case "127.0.0.1", "::1", "[::1]", "localhost":
		return models.ScopeLoopback, false
	}
	if strings.HasPrefix(a, "127.") {
		return models.ScopeLoopback, false
	}
	if strings.HasPrefix(a, "169.254.") {
		return models.ScopeLAN, false
	}
	if strings.HasPrefix(a, "fe80:") || strings.HasPrefix(a, "fe80::") {
		return models.ScopeLAN, false
	}
	if isPrivateIPv4(a) {
		return models.ScopeLAN, false
	}
	if strings.Contains(a, ":") {
		return models.ScopeLAN, false
	}
	return models.ScopeLAN, false
}

func isPrivateIPv4(a string) bool {
	parts := strings.Split(a, ".")
	if len(parts) != 4 {
		return false
	}
	nums := make([]int, 4)
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return false
		}
		nums[i] = v
	}
	switch {
	case nums[0] == 10:
		return true
	case nums[0] == 172 && nums[1] >= 16 && nums[1] <= 31:
		return true
	case nums[0] == 192 && nums[1] == 168:
		return true
	case nums[0] == 100 && nums[1] >= 64 && nums[1] <= 127:
		return true
	}
	return false
}

// ParseAddrPort splits a "host:port" pair, handling IPv6 bracket form.
func ParseAddrPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			host := stripZone(s[1:end])
			portStr := strings.TrimPrefix(s[end+1:], ":")
			p, _ := strconv.Atoi(portStr)
			return host, p
		}
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return stripZone(s), 0
	}
	host := s[:idx]
	p, _ := strconv.Atoi(s[idx+1:])
	if strings.Contains(host, ":") && !strings.HasPrefix(s, "[") {
		// Bare IPv6 without brackets and without a port.
		return stripZone(s), 0
	}
	return stripZone(host), p
}

// stripZone removes an IPv6 scope suffix such as %eth0. The zone identifies a
// link, not an address, so two sockets on the same address with different zones
// are one exposure and reporting them as two would inflate a finding.
func stripZone(a string) string {
	if i := strings.LastIndex(a, "%"); i > 0 {
		return a[:i]
	}
	return a
}
