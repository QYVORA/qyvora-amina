# Installing and updating

There are two ways to install Amina: the shared QYVORA installer, or the
self-updater. Both verify SHA-256 against the release's `checksums.txt` before
anything is executed.

## The installer

```sh
curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-amina/main/install.sh | bash
```

The installer detects the real target (kernel, CPU, userspace, ABI and runtime —
Android/Termux is a distinct target from ordinary Linux), resolves an artifact
name valid for that target, downloads over HTTPS, verifies the checksum and the
executable format (ELF class, machine, PIE-ness), then installs atomically into
the correct user executable directory and only adds it to `PATH` if needed.

Subcommands and overrides:

| Option | Effect |
|---|---|
| `--uninstall` | remove the binary and desktop integration (keeps user data) |
| `--prefix D` | install into `D` instead of the platform default |
| `--no-path` | install without touching your shell rc / PATH |
| `QYVORA_INSTALL_DIR` | override the install directory |
| `QYVORA_VERSION` | install a specific tag instead of latest |
| `QYVORA_SOURCE=1` | force a local source build, ignore prebuilt artifacts |
| `QYVORA_ALLOW_UNVERIFIED=1` | proceed without a checksum match (never recommended) |

On Windows use `install.ps1`.

## Self-update: `amina update`

This is the only operation Amina performs that writes to the host, and it does
nothing unless asked. It downloads from
`https://github.com/QYVORA/qyvora-amina/releases`, resolves the asset for the
running platform, and applies the following guarantees in order:

1. **Nothing is installed unless its SHA-256 matches the published manifest.**
   The manifest (`checksums.txt`) is fetched first and the digest is checked
   before the bytes are ever made executable.
2. **The candidate is proven to run before the old binary is replaced.** A
   release that does not start is never installed.
3. **The old binary is kept until the replacement is verified in place.** If the
   installed binary fails to run, the previous one is restored.
4. **The replacement is atomic.** The new binary is written beside the target and
   renamed over it, so an interrupted update leaves either the old binary or the
   new one, never a half-written file.

### Flags

| Flag | Effect |
|---|---|
| `--check` | verify a release and report, without installing; never prompts |
| `--dry-run` | download and verify, without installing |
| `--yes` | skip the confirmation prompt |
| `--version <tag>` | install a specific release tag (default: latest) |
| `--base-url <url>` | override release discovery (mirrors and testing) |
| `--timeout <n>` | give up after `n` seconds (default 120) |
| `--offline` | refuse to update (exits `3`) |
| `--insecure` | allow a plain-HTTP release; local mirrors only |

By default, installing prompts `replace the running binary with the latest
release? [y/N]`. Silence or anything other than `y`/`yes` is a no. This prompt
exists because a tool that can rewrite its own executable must not do so as a
side effect of being run.

```sh
# Is there a newer release?
amina update --check

# See exactly what it would replace, without changing anything
amina update --dry-run

# Install it
amina update
```

## Release artifacts

Each release publishes one bare executable per target (not a tarball) plus the
icons and one checksum manifest:

```
amina-linux-amd64
amina-linux-arm64
amina-macos-amd64
amina-macos-arm64
amina-windows-amd64.exe
amina-windows-arm64.exe
amina-android-arm64
amina.png
amina.ico
checksums.txt
```

The naming rule is `{tool}-{os}-{arch}[.exe]`, where `os` is
`linux | macos | windows | android`. Go calls the Apple platform `darwin`, but
the release, the installer and the self-updater all use `macos`; passing `GOOS`
straight through would look for `amina-darwin-arm64`, which no release
publishes.

The publishing workflow refuses to create a release unless every expected asset
is present, every artifact passes `scripts/verify-artifact.sh`, and the native
artifact actually starts. An Android artifact must be a position-independent
ELF (`ET_DYN`); a `GOOS=linux` build is `ET_EXEC` and Android's linker refuses
it, so it can never be published as an Android artifact.

## Verifying a download by hand

```sh
sha256sum -c checksums.txt --ignore-missing
```

`checksums.txt` covers the binaries and the icons, never itself.

## Building from source instead

See [DEVELOPMENT.md](DEVELOPMENT.md). A local build reports `dev` unless the
release ldflags stamp a version; release artifacts must never report `dev`.
