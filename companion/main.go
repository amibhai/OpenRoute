// OpenRoute native companion.
//
// One binary, four roles:
//   (no command)  native-messaging host — what the browser launches; a thin
//                 forwarder to the daemon (starts it when needed)
//   daemon        the supervisor that owns sing-box/tor and the desired state
//   install       registers the host with every installed browser (no admin)
//   uninstall     undoes that
//   doctor        a self-check
//
// Standard library only, so `go build` needs no network. The transport crypto
// lives in sing-box and tor, which this program orchestrates rather than
// reimplements.
package main

import (
	"fmt"
	"os"
)

var version = "1.0.0-dev"

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "daemon":
		os.Exit(runDaemon(os.Args[2:]))
	case "install":
		os.Exit(runInstall(os.Args[2:]))
	case "uninstall":
		os.Exit(runUninstall(os.Args[2:]))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("openroute-companion", version)
	case "help", "--help", "-h":
		fmt.Println("usage: openroute-companion [install [--extension-id ID,…] | uninstall | doctor | daemon | version]")
		fmt.Println("Run with no command, it acts as the browser's native-messaging host.")
	default:
		// Browsers launch us with the caller's origin (Chromium) or the
		// manifest path + add-on id (Firefox).
		os.Exit(runHost(os.Args[1:]))
	}
}
