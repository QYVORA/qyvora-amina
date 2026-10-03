//go:build !windows

package platform

import (
	"os"
	"strconv"
)

// currentIDs returns the numeric uid and gid.
//
// This needs its own file because os.Getuid and os.Getgid do not exist on
// Windows. A build that fails to compile on the platform the framework promises
// to support is a worse outcome than any capability it might have gained.
func currentIDs() (string, string) {
	return strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
}
