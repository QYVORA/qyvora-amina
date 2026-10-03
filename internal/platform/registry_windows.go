//go:build windows

package platform

import (
	"context"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// windowsUninstallPrograms reads the two uninstall registry keys that together
// cover per-machine and per-user installs.
//
// reg query is used instead of PowerShell because it works with no execution
// policy, no module loading and no profile, all three of which can be
// deliberately hostile on an assessed host. The registry is parsed into flat
// key/value pairs rather than through a registry library so the parse is
// identical in shape to every other collector's.
func windowsUninstallPrograms(ctx context.Context) ([]PackageQuery, models.SupportLevel) {
	roots := []struct {
		path     string
		view     string
		provider string
	}{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "reg", "windows-uninstall"},
		{`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "reg", "windows-uninstall"},
		{`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "reg", "windows-uninstall"},
	}

	seen := map[string]bool{}
	var out []PackageQuery
	level := models.SupportFull

	for _, r := range roots {
		text, err := Run(ctx, "reg", "query", r.path, "/s")
		if err != nil {
			level = models.SupportPrivilege
			continue
		}
		for _, entry := range parseRegQuery(text) {
			name := entry["DisplayName"]
			if name == "" || seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			out = append(out, PackageQuery{
				Name:     name,
				Version:  entry["DisplayVersion"],
				Provider: r.provider,
				// The publisher field is present but is self-asserted by the
				// installer, so it is not treated as provenance. Amina's own
				// signature check is what establishes where a binary came from.
				Origin: "unknown",
			})
		}
	}
	if len(out) == 0 {
		level = models.SupportPartial
	}
	return out, level
}
