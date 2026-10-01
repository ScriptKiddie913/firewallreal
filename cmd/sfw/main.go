// Package main implements the unified CLI tool sfw for SentinelGate & SentinelFW.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sentinelgate/sentinelgate/cmd/sfw/cmd"
)

var Version = "4.0.0"

func printUsage() {
	fmt.Println(`sfw - Unified command-line interface for SentinelGate and SentinelFW

Usage:
  sfw <command> [arguments]

Available Commands:
  version      Print SentinelGate / SentinelFW version
  policy       Inspect and manage firewall policies (list, check)
  commit       Commit candidate configuration to active ruleset
  confirm      Confirm pending configuration commit and cancel rollback
  rollback     Immediately rollback to previous configuration state
  tune         Display or apply kernel conntrack and network tuning
  routes       Display configured static and dynamic routes
  interfaces   Display network interfaces, zones, and offload flags
  top          Display real-time throughput, active sessions, and metrics
  sessions     List active stateful conntrack sessions
  alerts       Stream or view recent security threat alerts

Use "sfw <command> -h" for more information about a command.`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	subcmd := os.Args[1]
	args := os.Args[2:]

	switch subcmd {
	case "version", "-v", "--version":
		fs := flag.NewFlagSet("version", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "Output results in JSON format")
		fs.Parse(args)
		if *jsonOut {
			fmt.Printf(`{"version":"%s"}`+"\n", Version)
		} else {
			fmt.Printf("SentinelGate / SentinelFW CLI (sfw) version %s\n", Version)
		}
	case "policy":
		cmd.RunPolicy(args)
	case "commit":
		cmd.RunCommit(args)
	case "confirm":
		cmd.RunConfirm(args)
	case "rollback":
		cmd.RunRollback(args)
	case "tune":
		cmd.RunTune(args)
	case "routes":
		cmd.RunRoutes(args)
	case "interfaces":
		cmd.RunInterfaces(args)
	case "top":
		cmd.RunTop(args)
	case "sessions":
		cmd.RunSessions(args)
	case "alerts":
		cmd.RunAlerts(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'sfw help' for usage.\n", subcmd)
		os.Exit(1)
	}
}
