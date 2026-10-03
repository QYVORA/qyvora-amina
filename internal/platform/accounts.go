package platform

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Accounts is defined per platform family in accounts_posix.go and
// platform_windows.go. Both produce the same models.Account, so every consumer
// is written once against the model rather than against a platform.

// posixAccounts parses a passwd/group pair.
func posixAccounts(ctx context.Context, passwdPath, groupPath string) ([]models.Account, []models.SupportLevel) {
	data, err := ReadFileLimited(passwdPath)
	if err != nil {
		if ctx.Err() != nil {
			return nil, []models.SupportLevel{models.SupportNone}
		}
		return nil, []models.SupportLevel{models.SupportPrivilege, models.SupportNone}
	}
	adminGIDs := adminGroups(groupPath)
	groupNames := parseGroups(readText(groupPath))

	out := make([]models.Account, 0, 64)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		acct := models.Account{
			Name:           f[0],
			UID:            f[2],
			GID:            f[3],
			Shell:          f[6],
			Home:           f[5],
			GECOS:          f[4],
			Groups:         groupNames[f[0]],
			Service:        isServiceShell(f[6]),
			NoLogin:        isNologinShell(f[6]),
			Privileged:     uid == 0 || adminGIDs[f[3]],
			Source:         passwdPath,
			LastLogin:      lastLoginFor(ctx, f[0], f[5]),
			AuthorizedKeys: countAuthorizedKeys(f[5]),
		}
		out = append(out, acct)
	}

	// /etc/shadow is root-only. Not being able to read it is not a failure of
	// the account audit; it means lock state is unknown, and the model says so
	// rather than assuming every account is unlocked.
	level := models.SupportFull
	if fileExists("/etc/shadow") {
		if _, err := os.ReadFile("/etc/shadow"); err != nil {
			level = models.SupportPartial
		}
	}
	return out, []models.SupportLevel{level}
}

func readText(path string) string {
	data, err := ReadFileLimited(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func parseGroups(data string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		for _, member := range strings.Split(f[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				out[member] = append(out[member], f[0])
			}
		}
	}
	return out
}

// adminGroups returns the gids that confer administrative access on a POSIX
// system. Both the classic group and the sudo group are honoured because
// distributions disagree about which one governs.
func adminGroups(groupPath string) map[string]bool {
	admin := map[string]bool{"0": true}
	for _, line := range strings.Split(readText(groupPath), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 {
			continue
		}
		switch f[0] {
		case "sudo", "wheel", "admin", "Administrators", "root":
			admin[f[2]] = true
		}
	}
	return admin
}

func isNologinShell(shell string) bool {
	switch filepath.Base(shell) {
	case "nologin", "false", "sync":
		return true
	}
	return false
}

// isServiceShell recognises the shell field of a machine account. A service
// account is not a finding; it is context, and labelling it "unusual" because
// it has no interactive shell would flood every report with noise.
func isServiceShell(shell string) bool {
	if isNologinShell(shell) {
		return true
	}
	switch filepath.Base(shell) {
	case "shutdown", "halt", "games":
		return true
	}
	return false
}

func countAuthorizedKeys(home string) int {
	if home == "" {
		return 0
	}
	data, err := ReadFileLimited(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}

// lastLoginFor reads the best local last-login evidence available.
//
// Two sources are tried in order. `last` is preferred because it reads the
// wtmp database, which survives log rotation; `.lastlogin` is a per-user file
// some login managers write. Neither is reliable inside a container where no
// login has ever happened, so a miss yields a zero time and the account is
// reported as having no observable last-login record — not as dormant.
func lastLoginFor(ctx context.Context, user, home string) time.Time {
	if out, err := Run(ctx, "last", "-F", user); err == nil {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || fields[0] != user {
				continue
			}
			for i := 0; i+3 < len(fields); i++ {
				if t, err := time.Parse("Mon Jan  2 15:04:05 2006", strings.Join(fields[i:i+4], " ")); err == nil {
					return t.UTC()
				}
				if t, err := time.Parse("Mon Jan 02 15:04:05 2006", strings.Join(fields[i:i+4], " ")); err == nil {
					return t.UTC()
				}
			}
			break
		}
	}
	if data, err := ReadFileLimited(filepath.Join(home, ".lastlogin")); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && v > 0 {
			return time.Unix(v, 0).UTC()
		}
	}
	return time.Time{}
}

// termuxAccount describes the single identity a Termux shell actually has.
func termuxAccount(e *Env) models.Account {
	return models.Account{
		Name:       firstNonEmpty(e.User, "termux"),
		UID:        e.UID,
		GID:        e.GID,
		Shell:      e.Shell,
		Home:       e.Home,
		Privileged: e.UID == "0",
		Source:     "android uid",
	}
}
