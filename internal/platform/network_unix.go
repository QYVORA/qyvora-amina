//go:build !windows

package platform

import (
	"context"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

func interfaces(ctx context.Context, e *Env) ([]Interface, models.SupportLevel) {
	// Go's net package gives the same answer on every platform, so it is the
	// baseline rather than a fallback.
	ifaces := netInterfaces()
	if len(ifaces) == 0 {
		return nil, models.SupportLimited
	}
	level := models.SupportFull
	// On Windows the standard library cannot report bind scope, so ip is asked
	// as well. On POSIX, `ip` enriches what the standard library already knows.
	if out, err := Run(ctx, "ip", "-o", "addr"); err == nil && len(out) > 0 {
		if merged := mergeIPAddr(ifaces, out); merged != nil {
			ifaces = merged
		}
	}
	if e.Privileged {
		return ifaces, level
	}
	return ifaces, level
}

// mergeIPAddr folds `ip -o addr` output into the standard-library interface
// list, adding the CIDR-prefixed addresses the standard library omits.
func mergeIPAddr(in []Interface, out string) []Interface {
	byName := make(map[string]int, len(in))
	for i, iface := range in {
		byName[iface.Name] = i
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		name := f[1]
		idx, ok := byName[name]
		if !ok {
			continue
		}
		cidr := f[3]
		addr := cidr
		if i := strings.Index(cidr, "/"); i > 0 {
			addr = cidr[:i]
		}
		in[idx].Addrs = append(in[idx].Addrs, addr)
		kind, scope := classifyInterface(name, in[idx].Addrs)
		in[idx].Kind, in[idx].Scope = kind, scope
	}
	return in
}

// listeningSockets enumerates bound listeners using whichever of ss, netstat or
// lsof is installed, in preference order. All three are tried because a minimal
// container may ship only one, and a report that says "no open ports" because
// the one available tool was missing is the worst possible failure mode for
// this framework.
func listeningSockets(ctx context.Context, e *Env) ([]Socket, models.SupportLevel) {
	out, tool, err := RunFirst(ctx, [][]string{
		{"ss", "-tulnpH"},
		{"netstat", "-tuln"},
		{"netstat", "-an"},
	})
	if err != nil {
		out, tool, err = RunFirst(ctx, [][]string{{"lsof", "-nP", "-i", "-sTCP:LISTEN"}})
	}
	if err != nil || strings.TrimSpace(out) == "" {
		if err != nil {
			return nil, models.SupportNone
		}
		return nil, models.SupportLimited
	}
	socks := parseSS(out)
	if len(socks) == 0 && tool == "lsof" {
		socks = parseLSOF(out)
	}
	level := models.SupportFull
	// Process attribution needs /proc plus ownership of the socket; an
	// unprivileged run still sees listeners, just not who owns them.
	if !e.Privileged {
		level = models.SupportPartial
	}
	return socks, level
}

func parseSS(out string) []Socket {
	var socks []Socket
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		proto := strings.ToUpper(f[0])
		stateIdx := 0
		if strings.Contains(proto, "TCP") && len(f) > 4 {
			// `ss -tulnp` without -H inserts a state column for TCP rows.
			stateIdx = 1
		}
		local := f[1+stateIdx]
		addr, port := ParseAddrPort(local)
		scope, wild := classifyAddr(addr)
		s := Socket{Proto: proto, Addr: addr, Port: port, Scope: scope, Wildcard: wild}
		// users:(("nginx",pid=1234,fd=6)) appears in the final column.
		for _, tok := range f {
			if i := strings.Index(tok, `("`); i >= 0 {
				rest := tok[i+2:]
				if j := strings.Index(rest, `"`); j > 0 {
					s.Process = rest[:j]
				}
			}
			if i := strings.Index(tok, "pid="); i >= 0 {
				rest := tok[i+4:]
				end := strings.IndexAny(rest, ",)")
				if end > 0 {
					rest = rest[:end]
				}
				if pid, err := atoiSafe(rest); err == nil {
					s.PID = pid
				}
			}
		}
		socks = append(socks, s)
	}
	return socks
}

func parseLSOF(out string) []Socket {
	var socks []Socket
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		addr, port := ParseAddrPort(f[8])
		scope, wild := classifyAddr(addr)
		s := Socket{Proto: "TCP", Addr: addr, Port: port, Scope: scope, Wildcard: wild, Process: f[0]}
		socks = append(socks, s)
	}
	return socks
}
