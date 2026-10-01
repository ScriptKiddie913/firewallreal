// Package cmd implements the CLI subcommands for the sfw tool.
package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sentinelgate/sentinelgate/pkg/config"
)

var (
	configDir  = "/etc/sentinelgate"
	jsonOutput = false
)

func RunPolicy(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: sfw policy <list|check> [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("policy list", flag.ExitOnError)
		fs.StringVar(&configDir, "config-dir", "/etc/sentinelgate", "Configuration state directory")
		fs.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
		fs.Parse(args[1:])

		cm, err := config.NewConfigManager(configDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}
		active := cm.GetActive()

		if jsonOutput {
			data, _ := json.MarshalIndent(active.Policies, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("%-4s  %-24s  %-10s  %-10s  %-8s  %-12s  %s\n",
			"ID", "NAME", "SRC ZONE", "DST ZONE", "ACTION", "NAT", "SERVICES")
		fmt.Println("---------------------------------------------------------------------------------------------")
		for _, p := range active.Policies {
			natDesc := "none"
			if p.NAT != nil {
				natDesc = string(p.NAT.Type)
			}
			svcDesc := fmt.Sprintf("%v", p.Services)
			fmt.Printf("%-4d  %-24s  %-10s  %-10s  %-8s  %-12s  %s\n",
				p.ID, p.Name, p.SrcZone, p.DstZone, p.Action, natDesc, svcDesc)
		}

	case "check":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: sfw policy check <candidate.json>")
			os.Exit(1)
		}
		filePath := args[1]
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filePath, err)
			os.Exit(1)
		}

		var candidate config.GatewayConfig
		if err := json.Unmarshal(data, &candidate); err != nil {
			fmt.Fprintf(os.Stderr, "JSON parsing error: %v\n", err)
			os.Exit(1)
		}

		if err := candidate.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "[VALIDATION FAILED] %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[VALIDATION SUCCESS] Configuration syntax, zones, and rules are valid.")
	default:
		fmt.Fprintf(os.Stderr, "Unknown policy subcommand: %s\n", args[0])
		os.Exit(1)
	}
}
