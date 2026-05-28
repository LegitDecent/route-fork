package main

import (
	"os"

	"rofk/cli"
	guiApp "rofk/gui"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "validate":
			cli.RunValidate(os.Args[2:])
		case "scan":
			cli.RunScan(os.Args[2:])
		case "man":
			cli.PrintManPage()
		case "help", "--help", "-h", "-help":
			cli.PrintUsage()
		default:
			cli.RunFlatMode(os.Args[1:])
		}
		return
	}
	guiApp.Run()
}
