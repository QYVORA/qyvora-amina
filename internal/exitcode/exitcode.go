// Package exitcode defines the shared QYVORA process exit-code contract,
// extended with the ecosystem's "unsupported" code.
//
//	0   success
//	1   runtime failure (collection error, I/O error, internal error)
//	2   usage error (unknown flag/command, invalid value, missing/invalid target)
//	3   unsupported (the requested capability does not exist on this platform)
//	130 interrupted (128 + SIGINT)
//
// Amina needs the 3 code because its central promise is honest degradation. A
// caller that asks for a capability which genuinely does not exist here —
// systemd state on Windows, say — must be able to distinguish that from "the
// assessment ran and found nothing". Collapsing both into 0 is precisely the
// false-negative this framework exists to prevent.
package exitcode

const (
	Success     = 0
	Runtime     = 1
	Usage       = 2
	Unsupported = 3
	Interrupted = 130
)
