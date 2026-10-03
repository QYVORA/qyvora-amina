//go:build !windows

package platform

import (
	"io/fs"
	"os/user"
	"strconv"
	"syscall"
)

// ownerGroup holds resolved ownership names, falling back to numeric ids.
type ownerGroup struct {
	owner string
	group string
}

// statOwner extracts uid/gid from a stat result and resolves them to names.
//
// The uid/gid pair always comes from the filesystem even when name resolution
// is unavailable, because a report that says "owned by 0" is honest and a
// report that says "owner unknown" when the filesystem knew the answer is not.
func statOwner(fi fs.FileInfo) (ownerGroup, string) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ownerGroup{}, fi.Name()
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	gid := strconv.FormatUint(uint64(st.Gid), 10)
	owner, group := uid, gid
	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		owner = u.Username
	}
	if g, err := user.LookupGroupId(gid); err == nil && g.Name != "" {
		group = g.Name
	}
	return ownerGroup{owner: owner, group: group}, fi.Name()
}
