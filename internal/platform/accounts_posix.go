//go:build !windows

package platform

import (
	"context"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Accounts enumerates accounts the way this platform actually stores them.
//
// The Windows equivalent lives in platform_windows.go and returns the same
// model, so no collector above this layer carries a build tag.
func Accounts(ctx context.Context, e *Env) ([]models.Account, []models.SupportLevel) {
	switch e.Platform {
	case models.PlatformTermux:
		// Termux has no passwd database: a $PREFIX/etc/passwd may exist but
		// describes nothing about the Android uid the shell actually runs as.
		// Reporting a fabricated account list would be worse than reporting the
		// single real identity it does have, so the support level is "limited"
		// rather than full.
		return []models.Account{termuxAccount(e)}, []models.SupportLevel{models.SupportLimited}
	case models.PlatformDarwin:
		return posixAccounts(ctx, "/etc/passwd", "/etc/group")
	default:
		return posixAccounts(ctx, "/etc/passwd", "/etc/group")
	}
}
