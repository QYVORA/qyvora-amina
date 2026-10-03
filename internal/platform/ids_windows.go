//go:build windows

package platform

// currentIDs has no numeric equivalent on Windows: identity there is a SID and
// an account name, not a uid. The SecurityIdentifier authority and the primary
// group are what a Windows assessment should carry, and the platform model has
// room for them, so that is what is returned rather than a fabricated "0".
func currentIDs() (string, string) {
	return windowsSID(), "S-1-5-32-544"
}
