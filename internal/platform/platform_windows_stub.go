//go:build !windows

package platform

import (
	"context"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Windows-only collectors are reached through a shared dispatcher, so the
// dispatchers themselves stay free of build tags. These stubs exist only so the
// non-Windows build links; nothing calls them on this platform, because the
// dispatchers branch on Platform before ever reaching here.
//
// They return SupportNone rather than an empty slice with SupportFull, because
// if one of them were ever reached by mistake, "no services found" is exactly
// the wrong conclusion for a platform with no service manager of this kind.

func windowsServices(ctx context.Context, e *Env) ([]Service, models.SupportLevel) {
	return nil, models.SupportNone
}

func windowsUninstallPrograms(ctx context.Context) ([]PackageQuery, models.SupportLevel) {
	return nil, models.SupportNone
}
