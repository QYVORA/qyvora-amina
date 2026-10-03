//go:build windows

package platform

import (
	"io/fs"
)

// ownerGroup holds resolved ownership names. On Windows a file's identity is
// its ACL, not a uid, so the nearest honest equivalent is the account the file
// belongs to — which the callers obtain from the security module instead. This
// type exists so both builds share one signature.
type ownerGroup struct {
	owner string
	group string
}

// statOwner cannot answer ownership from a Windows stat call.
//
// Rather than pretending, it returns an empty owner and a filename, which makes
// OwnerGroup return empty strings and leads the file-permission collector to
// report ownership as "unavailable" for this platform. A fabricated owner name
// would be worse than an acknowledged gap.
func statOwner(fi fs.FileInfo) (ownerGroup, string) {
	return ownerGroup{}, fi.Name()
}
