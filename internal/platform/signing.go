package platform

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// FileSignature is what a platform's signature tooling could establish about one
// file. Every field is optional because no platform's tooling establishes all of
// them, and a field that could not be determined is absent rather than empty —
// the distinction matters, since "unsigned" and "signature not checked" are
// different findings with different severities.
type FileSignature struct {
	Path        string `json:"path"`
	Signed      bool   `json:"signed"`
	Verified    bool   `json:"verified"`
	Publisher   string `json:"publisher,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Subject     string `json:"subject,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
	Method      string `json:"method"`
	Note        string `json:"note,omitempty"`
}

// VerifySignature inspects one file's code signature.
//
// The three platforms that have code signing each answer the question with
// their own tool, and the three answers are normalised into one shape. A file
// that cannot be inspected reports Verified false with a note naming why — it
// never reports Verified true because the tool was missing.
func VerifySignature(ctx context.Context, e *Env, path string) FileSignature {
	sig := FileSignature{Path: path}
	if !fileExists(path) {
		sig.Note = "file not present"
		sig.Method = "none"
		return sig
	}
	switch e.Platform {
	case models.PlatformWindows:
		return verifyAuthenticode(ctx, path, sig)
	case models.PlatformDarwin:
		return verifyCodesign(ctx, path, sig)
	default:
		return verifyELF(ctx, path, sig)
	}
}

// verifyAuthenticode uses PowerShell's signature check because no other
// built-in binary exposes the certificate chain.
func verifyAuthenticode(ctx context.Context, path string, sig FileSignature) FileSignature {
	sig.Method = "authenticode"
	script := "Get-AuthenticodeSignature -LiteralPath '" +
		strings.ReplaceAll(path, "'", "''") + "' | " +
		"Select-Object Status,StatusMessage,SignerCertificate,TimeStamperCertificate | " +
		"ConvertTo-Json -Compress"
	out, err := Run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		sig.Note = "authenticode inspection unavailable: " + err.Error()
		return sig
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		fields := parseJSONObject(line)
		switch strings.ToUpper(fields["Status"]) {
		case "VALID":
			sig.Signed, sig.Verified = true, true
		case "NOTSIGNED":
			sig.Note = "file carries no Authenticode signature"
		case "HASHMISATCH", "NOTTRUSTED", "INVALID":
			sig.Signed = true
			sig.Note = "signature present but not valid: " + fields["StatusMessage"]
		default:
			if v := fields["Status"]; v != "" {
				sig.Note = "authenticode status: " + v
			}
		}
		if c := fields["SignerCertificate"]; c != "" {
			sig.Publisher = jsonStringField(c, "Subject")
			sig.Issuer = jsonStringField(c, "Issuer")
			sig.Certificate = jsonStringField(c, "Thumbprint")
			if d := jsonStringField(c, "NotAfter"); d != "" {
				sig.NotAfter = d
			}
		}
	}
	return sig
}

// verifyCodesign uses `codesign -dv` for the signature and a separate
// `--verify` for the trust decision, because `codesign -dv` reports that a
// signature exists whether or not it validates — a distinction Amina needs.
func verifyCodesign(ctx context.Context, path string, sig FileSignature) FileSignature {
	sig.Method = "codesign"
	display, err := Run(ctx, "codesign", "-dv", "--verbose=4", path)
	if err != nil {
		sig.Note = "no code signature: " + strings.TrimSpace(display)
		return sig
	}
	sig.Signed = true
	for _, line := range strings.Split(display, "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok {
			switch strings.TrimSpace(k) {
			case "Authority":
				if sig.Issuer == "" {
					sig.Issuer = strings.TrimSpace(v)
				} else {
					sig.Publisher = strings.TrimSpace(v)
				}
			case "TeamIdentifier":
				sig.Certificate = strings.TrimSpace(v)
			}
		}
	}
	if verify, verr := Run(ctx, "codesign", "--verify", "--strict", "--verbose=2", path); verr != nil {
		sig.Note = "signature present but verification failed: " + strings.TrimSpace(verify)
		return sig
	}
	sig.Verified = true
	return sig
}

// verifyELF has no equivalent on Linux, where the only comparable mechanism is
// package-manager ownership, which is a provenance question rather than a
// signature question. Reporting "unsigned" here would be wrong: most Linux
// binaries carry no signature at all and that is normal, not a finding.
func verifyELF(ctx context.Context, path string, sig FileSignature) FileSignature {
	sig.Method = "none"
	sig.Note = "no per-file code signing on this platform; provenance is established by package ownership instead"
	return sig
}

// PackageOwners answers "which package owns this file", which on Linux is the
// only trustworthy provenance signal and the reason the provenance module can
// still reach a verdict on Linux.
func PackageOwners(ctx context.Context, e *Env, paths []string) (map[string]string, models.SupportLevel) {
	out := map[string]string{}
	if len(paths) == 0 {
		return out, models.SupportFull
	}

	var query []string
	switch {
	case HasCommand("dpkg-query"):
		query = []string{"dpkg-query", "-S"}
		query = append(query, paths...)
	case HasCommand("rpm"):
		query = []string{"rpm", "-qf"}
		query = append(query, paths...)
	case HasCommand("pacman"):
		query = []string{"pacman", "-Qo"}
		query = append(query, paths...)
	case HasCommand("pkg"):
		query = []string{"pkg", "search"}
		for _, p := range paths {
			query = append(query, filepath.Base(p))
		}
	default:
		return out, models.SupportPartial
	}

	text, err := Run(ctx, query[0], query[1:]...)
	if err != nil && strings.TrimSpace(text) == "" {
		return out, models.SupportPrivilege
	}
	for _, line := range strings.Split(text, "\n") {
		// Every one of these managers answers "path: owner", but the manager
		// names differ: dpkg says "package: arch", rpm adds a package version.
		i := strings.Index(line, ": ")
		if i <= 0 {
			continue
		}
		out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+2:])
	}
	level := models.SupportFull
	if !e.Privileged {
		level = models.SupportPartial
	}
	return out, level
}

// VerifyPackageIntegrity checks the package manager's own view of whether
// installed files still match their recorded checksums.
//
// This is the strongest provenance signal available anywhere: a modified binary
// in /usr/bin shows up here even when it still carries the right ownership. It
// is also expensive, so Amina treats a missing result as unknown rather than as
// "no tampering".
func VerifyPackageIntegrity(ctx context.Context, e *Env) ([]string, models.SupportLevel) {
	switch {
	case HasCommand("debsums"):
		out, err := Run(ctx, "debsums", "--silent")
		if err != nil {
			return nil, models.SupportPartial
		}
		var bad []string
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "DEBCHECK") {
				bad = append(bad, strings.TrimSpace(line))
			}
		}
		return bad, models.SupportFull
	case HasCommand("rpm"):
		out, err := Run(ctx, "rpm", "-Va", "--nomtime", "--nofiledigest")
		if err != nil || strings.TrimSpace(out) == "" {
			return nil, models.SupportPartial
		}
		var bad []string
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			// A '5' in the MD5 digest column is rpm's way of saying the file
			// no longer matches what the package recorded.
			if len(f) >= 4 && strings.Contains(f[3], "5") {
				bad = append(bad, strings.Join(f, " "))
			}
		}
		return bad, models.SupportFull
	case HasCommand("pacman"):
		out, err := Run(ctx, "pacman", "-Qkk")
		if err != nil {
			return nil, models.SupportPartial
		}
		var bad []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "modified") || strings.Contains(line, "unexpected") {
				bad = append(bad, strings.TrimSpace(line))
			}
		}
		return bad, models.SupportFull
	case e.Platform == models.PlatformDarwin && HasCommand("codesign"):
		return nil, models.SupportLimited
	case e.Platform == models.PlatformTermux && HasCommand("pkg"):
		out, err := Run(ctx, "pkg", "audit")
		if err != nil {
			return nil, models.SupportLimited
		}
		var bad []string
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != "" {
				bad = append(bad, strings.TrimSpace(line))
			}
		}
		return bad, models.SupportFull
	default:
		return nil, models.SupportPartial
	}
}

// parseJSONObject extracts top-level string fields from a flat JSON object.
// It exists instead of encoding/json because the callers are parsing single-line
// tool output where a full unmarshal would fail on nested certificate objects,
// and it tolerates those nested values by ignoring everything that is not a
// scalar.
func parseJSONObject(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for {
		i = strings.IndexByte(s[i:], '"')
		if i < 0 {
			break
		}
		i += len(s[i:])
		keyStart := i
		end := strings.IndexByte(s[i:], '"')
		if end < 0 {
			break
		}
		key := s[keyStart : keyStart+end]
		rest := strings.TrimSpace(s[keyStart+end+1:])
		if !strings.HasPrefix(rest, ":") {
			i = keyStart + end + 1
			continue
		}
		val := strings.TrimSpace(rest[1:])
		switch {
		case strings.HasPrefix(val, `"`):
			if e := strings.IndexByte(val[1:], '"'); e >= 0 {
				out[key] = val[1 : 1+e]
				i = keyStart + end + 1 + 1 + e + 1
			} else {
				i = len(s)
			}
		case strings.HasPrefix(val, "{"), strings.HasPrefix(val, "["):
			depth, j := 0, 0
			for ; j < len(val); j++ {
				switch val[j] {
				case '{', '[':
					depth++
				case '}', ']':
					depth--
				}
				if depth == 0 {
					break
				}
			}
			i = keyStart + end + 1 + 1 + j
		default:
			k := 0
			for k < len(val) && val[k] != ',' && val[k] != '}' {
				k++
			}
			out[key] = strings.TrimSpace(val[:k])
			i = keyStart + end + 1 + 1 + k
		}
	}
	return out
}

// jsonStringField extracts one field from a nested JSON object, used for the
// certificate objects PowerShell embeds in its signature output.
func jsonStringField(obj, field string) string {
	if obj == "" {
		return ""
	}
	needle := `"` + field + `"`
	i := strings.Index(obj, needle)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(obj[i+len(needle):])
	if !strings.HasPrefix(rest, ":") {
		return ""
	}
	rest = strings.TrimSpace(rest[1:])
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	if e := strings.IndexByte(rest[1:], '"'); e >= 0 {
		return rest[1 : 1+e]
	}
	return ""
}

// fileExe reports whether a file looks like an executable, used to bound which
// files the provenance module inspects. Magic bytes are checked rather than the
// file extension because an attacker controls the extension and not the header.
func fileIsExecutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	switch {
	case magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		return true
	case magic[0] == 'M' && magic[1] == 'Z': // PE/COFF, includes .exe and .dll
		return true
	case magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe:
		return true // Mach-O 64-bit
	case magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && magic[3] == 0xce:
		return true // Mach-O 32-bit
	case magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe:
		return true // Java class / Mach-O universal
	case magic[0] == '#' && magic[1] == '!':
		return true // script with interpreter line
	}
	return false
}
