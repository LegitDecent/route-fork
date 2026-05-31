package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"rofk/cli"
	guiApp "rofk/gui"
)

// version is injected at build time via -ldflags "-X main.version=...".
// It falls back to the module version stamped by the Go toolchain (or "dev").
var version = ""

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "validate":
			cli.RunValidate(os.Args[2:])
		case "scan":
			cli.RunScan(os.Args[2:])
		case "man":
			cli.PrintManPage()
		case "version", "--version", "-v":
			fmt.Printf("rofk %s %s/%s %s\n", resolveVersion(), runtime.GOOS, runtime.GOARCH, runtime.Version())
		case "help", "--help", "-h", "-help":
			cli.PrintUsage()
		default:
			cli.RunFlatMode(os.Args[1:])
		}
		return
	}
	guiApp.Run()
}
