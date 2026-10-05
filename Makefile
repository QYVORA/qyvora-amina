BINARY := amina
# The common contract requires a semver version and rejects "dev", so the
# default has to match the value compiled into internal/version. Overriding it
# is a release step, not a build-time convenience: `make build` with the
# default is what keeps an amina binary conforming.
VERSION ?= v0.1.0
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
USER    ?= $(shell id -u -n)
GOFLAGS := -ldflags="-s -w -X github.com/QYVORA/qyvora-amina/internal/version.Version=$(VERSION) -X github.com/QYVORA/qyvora-amina/internal/version.Commit=$(COMMIT) -X github.com/QYVORA/qyvora-amina/internal/version.Date=$(DATE) -X github.com/QYVORA/qyvora-amina/internal/version.BuildUser=$(USER)" -trimpath

PREFIX ?= /usr/local
DESTDIR ?=

# --- install layout ------------------------------------------------------
# System-wide install (default PREFIX=/usr/local, typically needs root):
#   /usr/local/bin/amina              command
#   /usr/local/share/applications/    desktop entry (searchable in the app menu)
#   /usr/local/share/icons/hicolor/512x512/apps/amina.png
#   /usr/local/share/pixmaps/amina.png
# User install (make install-user) mirrors the same layout under ~/.local.

ICON    := assets/amina.png
DESKTOP := assets/amina.desktop

BINDIR    := $(DESTDIR)$(PREFIX)/bin
ICONDIR   := $(DESTDIR)$(PREFIX)/share/icons/hicolor/512x512/apps
PIXMAPDIR := $(DESTDIR)$(PREFIX)/share/pixmaps
APPDIR    := $(DESTDIR)$(PREFIX)/share/applications

USERBIN    := $(HOME)/.local/bin
USERICON   := $(HOME)/.local/share/icons/hicolor/512x512/apps
USERPIXMAP := $(HOME)/.local/share/pixmaps
USERAPP    := $(HOME)/.local/share/applications

.PHONY: all build install install-data install-user uninstall uninstall-user test test-race vet lint verify clean

all: lint vet test build

build:
	go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/amina

test:
	go test ./... -count=1 -timeout 60s

test-race:
	go test -race ./... -count=1 -timeout 120s

vet:
	go vet ./...

lint:
	golangci-lint run ./...

verify: lint vet test-race build
	@echo "ALL CHECKS PASSED"

install: build
	install -d $(BINDIR)
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	$(MAKE) install-data

# The desktop entry and the icon are installed independently of each other. The
# entry is the part a person uses; the icon is decoration, and this tree has no
# amina.png to ship. Tying them together meant a missing icon silently cost the
# menu entry too, so a missing asset could still take a working tool's
# discoverability down with it. The binary is already in place before this runs,
# and a user without a menu entry still has a working tool.
install-data:
	@if [ -f "$(DESKTOP)" ]; then \
		install -d $(APPDIR); \
		sed -e 's|@PREFIX@|$(PREFIX)|g' $(DESKTOP) > $(APPDIR)/amina.desktop; \
		chmod 0644 $(APPDIR)/amina.desktop; \
		update-desktop-database $(APPDIR) 2>/dev/null || true; \
	else \
		echo "amina: $(DESKTOP) missing; installed the command without a menu entry."; \
	fi
	@if [ -f "$(ICON)" ]; then \
		install -d $(ICONDIR) $(PIXMAPDIR); \
		install -m 0644 $(ICON) $(ICONDIR)/amina.png; \
		install -m 0644 $(ICON) $(PIXMAPDIR)/amina.png; \
		gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true; \
	else \
		echo "amina: $(ICON) missing; menu entry installed without an icon."; \
	fi

install-user: build
	install -d $(USERBIN)
	install -m 0755 bin/$(BINARY) $(USERBIN)/$(BINARY)
	@if [ -f "$(DESKTOP)" ]; then \
		install -d $(USERAPP); \
		sed -e 's|@PREFIX@|$(HOME)/.local|g' $(DESKTOP) > $(USERAPP)/amina.desktop; \
		chmod 0644 $(USERAPP)/amina.desktop; \
		update-desktop-database $(USERAPP) 2>/dev/null || true; \
	else \
		echo "amina: $(DESKTOP) missing; installed the command without a menu entry."; \
	fi
	@if [ -f "$(ICON)" ]; then \
		install -d $(USERICON) $(USERPIXMAP); \
		install -m 0644 $(ICON) $(USERICON)/amina.png; \
		install -m 0644 $(ICON) $(USERPIXMAP)/amina.png; \
		gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true; \
	else \
		echo "amina: $(ICON) missing; menu entry installed without an icon."; \
	fi
	@echo "Add $$HOME/.local/bin to your PATH if it is not already there."

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(ICONDIR)/amina.png $(PIXMAPDIR)/amina.png $(APPDIR)/amina.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true

uninstall-user:
	rm -f $(USERBIN)/$(BINARY)
	rm -f $(USERICON)/amina.png $(USERPIXMAP)/amina.png $(USERAPP)/amina.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true

clean:
	rm -f $(BINARY)
	rm -rf bin releases/
