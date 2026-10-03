package platform

import (
	"net"
	"strconv"
)

// Thin wrappers over the standard library, kept as functions rather than used
// inline so the Windows build can override only what it must.

func interfaceNames() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		out = append(out, iface.Name)
	}
	return out, nil
}

func interfaceAddrs(name string) []string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			out = append(out, v.IP.String())
		case *net.IPAddr:
			out = append(out, v.IP.String())
		}
	}
	return out
}

func interfaceUp(name string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	return iface.Flags&net.FlagUp != 0
}

func interfaceMAC(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	return iface.HardwareAddr.String()
}

func atoiSafe(s string) (int, error) { return strconv.Atoi(s) }
