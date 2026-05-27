PREFIX  ?= /usr/local
BINDIR   = $(PREFIX)/bin
MANDIR   = $(PREFIX)/share/man/man1
BINARY   = proxy-manager
MANSRC   = docs/proxy-manager.1

.PHONY: all build install install-bin install-man uninstall clean

all: build

build:
	go build -o $(BINARY) .

install: build install-bin install-man
	@echo ""
	@echo "Installed $(BINARY) to $(BINDIR)/$(BINARY)"
	@echo "Man page   installed at $(MANDIR)/$(BINARY).1"
	@echo ""
	@echo "Try: proxy-manager help"
	@echo "     man proxy-manager"

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

clean:
	rm -f $(BINARY)
