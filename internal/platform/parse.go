package platform

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Small parsing helpers shared by the collectors. They are plain functions
// rather than methods because they are pure text handling with no platform
// behaviour, and hiding them in the platform layer would imply otherwise.

// readDirNames lists the entries of a directory. A directory that cannot be
// read yields no names: the callers are all probing optional locations, and a
// failed probe and an empty directory mean the same thing to them.
func readDirNames(path string) []string {
	entries, _ := os.ReadDir(path)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// globNames lists the entries of dir matching a simple shell pattern. Only the
// trailing-`*` and `*.ext` forms are supported, because those are the only ones
// the persistence collectors need and a general glob would pull in a dependency
// for no benefit.
func globNames(dir, pattern string) []string {
	entries := readDirNames(dir)
	out := make([]string, 0, len(entries))
	for _, name := range entries {
		if !matchPattern(name, pattern) {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Strings(out)
	return out
}

func matchPattern(name, pattern string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*."):
		return strings.HasSuffix(name, pattern[1:])
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(name, pattern[:len(pattern)-1])
	default:
		return name == pattern
	}
}

func trimBase(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

// cutPrefix is strings.CutPrefix, spelled out because the codebase targets the
// Go version in go.mod and keeps its own helpers explicit for readability.
func cutPrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

func atoiOr(s string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return v
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// sizeUnits is ordered longest-suffix-first and is never ranged over as a map.
// A map would make this function non-deterministic: for "2 MiB" it might match
// "B" before "MiB" and fail to parse the remainder, which is exactly the kind
// of intermittent parse failure that turns into a silently wrong size.
var sizeUnits = []struct {
	suffix string
	mult   float64
}{
	{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3},
	{"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10},
	{"B", 1},
}

// trimUnit strips a trailing unit suffix from a number, so that "1234kB" and
// "1234 KB" both compare as equal to a byte count.
func trimUnit(s string) (float64, error) {
	s = strings.TrimSpace(s)
	mult := 1.0
	for _, u := range sizeUnits {
		if len(s) > len(u.suffix) && strings.EqualFold(s[len(s)-len(u.suffix):], u.suffix) {
			s = strings.TrimSpace(s[:len(s)-len(u.suffix)])
			mult = u.mult
			break
		}
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	return v * mult, nil
}

// parseRegQuery flattens `reg query /s` output into key/value pairs, one map
// per subkey.
//
// Values are located by their REG_ type token rather than by column, because
// reg.exe pads the name and the type to different widths and any fixed-width
// assumption breaks on the next Windows release. Continuations of a multi-line
// value are appended to the value they belong to instead of being dropped,
// since dropping them silently truncates version strings.
func parseRegQuery(text string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	lastKey := ""

	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
		}
		cur = map[string]string{}
		lastKey = ""
	}

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "HKEY_") || strings.HasPrefix(trimmed, "\\") {
			flush()
			continue
		}
		name, value, ok := parseRegValueLine(trimmed)
		if !ok {
			continue
		}
		if lastKey == name {
			cur[name] += "; " + value
			continue
		}
		lastKey = name
		cur[name] = value
	}
	flush()
	return out
}

// parseRegValueLine parses one indented "Name    REG_TYPE    value" line.
func parseRegValueLine(trimmed string) (name, value string, ok bool) {
	i := strings.Index(trimmed, "    REG_")
	if i < 0 {
		return "", "", false
	}
	name = strings.TrimSpace(trimmed[:i])
	rest := strings.TrimSpace(trimmed[i+len("    REG_"):])
	// Drop the type token (SZ, EXPAND_SZ, DWORD, ...) to reach the value.
	if sp := strings.IndexAny(rest, " \t"); sp >= 0 {
		rest = strings.TrimSpace(rest[sp+1:])
	} else {
		return "", "", false
	}
	if strings.HasPrefix(rest, `"`) && strings.HasSuffix(rest, `"`) && len(rest) >= 2 {
		rest = rest[1 : len(rest)-1]
	}
	if name == "" {
		return "", "", false
	}
	return name, rest, true
}

// parseCSVLine splits one CSV row, honouring quoted fields that contain commas
// or escaped quotes. A naive strings.Split would mangle every task whose name
// contains a comma, which is common in Microsoft product tasks.
func parseCSVLine(line string) []string {
	var out []string
	var cur strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				cur.WriteByte('"')
				i++
				continue
			}
			inQuotes = !inQuotes
		case c == ',' && !inQuotes:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}
