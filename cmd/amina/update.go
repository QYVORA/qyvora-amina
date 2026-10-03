package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/exitcode"
	"github.com/QYVORA/qyvora-amina/internal/update"
)

// releaseRepo is where Amina's releases live. It is spelled out here rather than
// inferred from the module path so that a forked or vendored binary keeps talking
// to the upstream it was built from unless it is told otherwise.
const releaseRepo = "QYVORA/qyvora-amina"

// runUpdate implements `amina update`.
//
// This is the only code path in Amina that writes to the host or reaches the
// network, which is why it is worth being fussy about: the download is verified
// against the release checksum, the candidate is executed before it is
// installed, and the original is kept until the replacement is in place.
func runUpdate(ctx context.Context, args []string) int {
	var (
		checkOnly bool
		dryRun    bool
		assumeYes bool
		tag       string
		baseURL   string
		timeout   int
		offline   bool
		insecure  bool
	)

	fs := flag.NewFlagSet("amina update", flag.ContinueOnError)
	fs.Usage = func() { _, _ = fmt.Fprint(fs.Output(), updateUsage) }
	fs.BoolVar(&checkOnly, "check", false, "report whether a newer verified release exists, and stop")
	fs.BoolVar(&dryRun, "dry-run", false, "download and verify the release without installing it")
	fs.BoolVar(&assumeYes, "yes", false, "skip the confirmation prompt")
	fs.StringVar(&tag, "version", "", "release tag to install (default: latest)")
	fs.StringVar(&baseURL, "base-url", "", "override release discovery (testing and mirrors)")
	fs.IntVar(&timeout, "timeout", 120, "give up after this many seconds")
	fs.BoolVar(&offline, "offline", false, "refuse to update")
	fs.BoolVar(&insecure, "insecure", false, "allow a plain-HTTP release; for local mirrors only")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage
	}
	if rest := fs.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "amina update: unexpected argument %q\n", rest[0])
		return exitcode.Usage
	}

	opts := update.Options{
		Repo:     releaseRepo,
		Version:  tag,
		BaseURL:  baseURL,
		DryRun:   dryRun,
		Timeout:  timeoutSeconds(timeout),
		Insecure: insecure,
		Out:      os.Stderr,
	}

	if offline {
		fmt.Fprintf(os.Stderr, "amina: %v\n", update.ErrOffline)
		return exitcode.Unsupported
	}

	// A check is the safe form of an update: it verifies everything and reports,
	// and never prompts, because it never asks for permission to change anything.
	opts.DryRun = dryRun || checkOnly

	if !opts.DryRun && !assumeYes {
		ok, err := confirmUpdate(tag, os.Stdin, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "amina update: %v\n", err)
			return exitcode.Runtime
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "amina update: cancelled; nothing was changed")
			return exitcode.Success
		}
	}

	res, err := update.Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amina update: %v\n", err)
		if checkOnly {
			// "There is no usable release" is the answer, not a crash.
			return exitcode.Unsupported
		}
		return exitcode.Runtime
	}

	switch {
	case checkOnly:
		fmt.Fprintf(os.Stderr, "\namina %s is available (%s, sha256 %s)\n",
			res.ToVersion, res.Artifact, shortDigest(res.Digest))
		fmt.Fprintln(os.Stderr, "Run `amina update` to install it.")
	case dryRun:
		fmt.Fprintf(os.Stderr, "\ndry run: %s verified (%s, sha256 %s) and would replace %s\n",
			res.ToVersion, res.Artifact, shortDigest(res.Digest), res.Path)
	default:
		fmt.Fprintf(os.Stderr, "\nupdated %s: %s -> %s\n", res.Path, res.FromVersion, res.ToVersion)
		fmt.Fprintf(os.Stderr, "sha256 %s\n", res.Digest)
	}
	return exitcode.Success
}

// confirmUpdate asks before replacing the running binary.
//
// A tool that can rewrite its own executable must not do it as a side effect of
// being run with no arguments, so this prompt is on by default. --yes skips it
// for CI and for anyone who has made the decision already.
func confirmUpdate(tag string, in io.Reader, out io.Writer) (bool, error) {
	which := "the latest release"
	if strings.TrimSpace(tag) != "" {
		which = "release " + tag
	}
	_, _ = fmt.Fprintf(out, "amina update: replace the running binary with %s? [y/N] ", which)

	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		// No input at all: treat silence as a no, rather than assuming consent.
		_, _ = fmt.Fprintln(out)
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// shortDigest trims a digest for display. The full value is in the manifest.
func shortDigest(d string) string {
	if len(d) > 16 {
		return d[:16] + "..."
	}
	return d
}

// timeoutSeconds converts a second count for Options.Timeout.
func timeoutSeconds(n int) time.Duration { return time.Duration(n) * time.Second }

const updateUsage = `usage: amina update [flags]

Replace the running binary with a checksum-verified release.

This is the only thing amina will ever write to the host, and it does not do so
unless you ask it to.

flags:
  --check             verify a release and report, without installing
  --dry-run           download and verify, without installing
  --yes               skip the confirmation prompt
  --version string    release tag to install (default: latest)
  --base-url string   override release discovery (mirrors and testing)
  --timeout int       give up after N seconds (default 120)
  --offline           refuse to update
  --insecure          allow a plain-HTTP release (local mirrors only)
`
