PREFIX  ?= /usr/local
BINDIR   = $(PREFIX)/bin
MANDIR   = $(PREFIX)/share/man/man1
BINARY   = rofk
MANSRC   = docs/rofk.1
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

PLATFORMS = \
  linux/amd64 \
  linux/arm64 \
  darwin/amd64 \
  darwin/arm64 \
  windows/amd64

.PHONY: all build install install-bin install-man uninstall release clean

all: build

build:
	go build -trimpath -ldflags="-s -w" -o $(BINARY) .

# install from local source (requires Go)
install: build install-bin install-man
	@echo ""
	@echo "  Installed $(BINARY) to $(BINDIR)/$(BINARY)"
	@echo "  Man page at $(MANDIR)/$(BINARY).1"
	@echo ""
	@echo "  nmap is needed for nmap mode (built-in scanner needs nothing extra):"
	@echo "    macOS:   brew install nmap"
	@echo "    Linux:   apt/dnf install nmap"

install-bin: build
	install -d $(BINDIR)
	install -m 755 $(BINARY) $(BINDIR)/$(BINARY)

install-man:
	install -d $(MANDIR)
	install -m 644 $(MANSRC) $(MANDIR)/$(BINARY).1

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(MANDIR)/$(BINARY).1
	@echo "Uninstalled."

# build release binaries for all platforms into dist/
release:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$$(echo $$p | cut -d/ -f1); \
	  arch=$$(echo $$p | cut -d/ -f2); \
	  out=dist/$(BINARY)-$${os}-$${arch}; \
	  [ "$$os" = "windows" ] && out="$$out.exe"; \
	  echo "  building $$os/$$arch → $$out"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
	    go build -trimpath -ldflags="-s -w" -o $$out . ; \
	done
	@echo ""
	@echo "Release binaries in dist/:"
	@ls -lh dist/

clean:
	rm -f $(BINARY)
	rm -rf dist/
