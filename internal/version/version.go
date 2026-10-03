// Package version holds build identity for the amina binary. The values are
// compile-time defaults; release builds stamp them via:
//
//	go build -ldflags "-X github.com/QYVORA/qyvora-amina/internal/version.Version=<tag> ..."
//
// Unstamped dev builds report "dev". Release artifacts must never report a dev
// build (QYVORA output spec), which is why the conformance stage asserts
// semver.
package version

import "runtime"

// Framework is the canonical framework name carried in events and reports.
const Framework = "amina"

// Purpose is the one-line domain statement used in banners and docs.
const Purpose = "Operational Security / Host Exposure Assessment Framework"

// Public QYVORA organisation details, kept in one place.
const (
	CompanyName  = "QYVORA OffSec"
	CompanyURL   = "https://qyvora.netlify.app"
	CompanyEmail = "qyvorasec@gmail.com"
	CompanyCity  = "Tamale, Ghana"
)

var (
	Version   = "v0.1.0"
	Commit    = "none"
	Date      = "unknown"
	BuildUser = "unknown"
)

// Info is the machine-readable build identity.
type Info struct {
	Framework string `json:"framework"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	BuildUser string `json:"build_user"`
	GoVersion string `json:"go_version"`
	Arch      string `json:"arch"`
	OS        string `json:"os"`
	Website   string `json:"website"`
	Support   string `json:"support"`
	BuiltIn   string `json:"built_in"`
}

// GetInfo returns the full build identity.
func GetInfo() Info {
	return Info{
		Framework: Framework,
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		BuildUser: BuildUser,
		GoVersion: runtime.Version(),
		Arch:      runtime.GOARCH,
		OS:        runtime.GOOS,
		Website:   CompanyURL,
		Support:   CompanyEmail,
		BuiltIn:   CompanyCity,
	}
}

// String returns the short version string used by the CLI and console.
func String() string { return Version }
