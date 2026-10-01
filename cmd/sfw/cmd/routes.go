package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sentinelgate/sentinelgate/pkg/config"
)

func RunRoutes(args []string) {
	fs := flag.NewFlagSet("routes", flag.ExitOnError)
	fs.StringVar(&configDir, "config-dir", "/etc/sentinelgate", "Configuration state directory")
	fs.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	fs.Parse(args)

	cm, err := config.NewConfigManager(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg := cm.GetActive()

	if jsonOutput {
		data, _ := json.MarshalIndent(cfg.StaticRoutes, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("%-24s  %-16s  %-12s  %s\n", "DESTINATION", "GATEWAY", "INTERFACE", "METRIC")
	fmt.Println("----------------------------------------------------------------------")
	for _, r := range cfg.StaticRoutes {
		intf := r.Interface
		if intf == "" {
			intf = "auto"
		}
		fmt.Printf("%-24s  %-16s  %-12s  %d\n", r.Destination, r.Gateway, intf, r.Metric)
	}
}

func RunInterfaces(args []string) {
	fs := flag.NewFlagSet("interfaces", flag.ExitOnError)
	fs.StringVar(&configDir, "config-dir", "/etc/sentinelgate", "Configuration state directory")
	fs.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	fs.Parse(args)

	cm, err := config.NewConfigManager(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	cfg := cm.GetActive()

	if jsonOutput {
		data, _ := json.MarshalIndent(cfg.Interfaces, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("%-10s  %-10s  %-8s  %s\n", "INTERFACE", "ZONE", "OFFLOAD", "IP ADDRESSES")
	fmt.Println("----------------------------------------------------------------------")
	for _, itf := range cfg.Interfaces {
		offloadStr := "disabled"
		if itf.Offload {
			offloadStr = "enabled"
		}
		fmt.Printf("%-10s  %-10s  %-8s  %v\n", itf.Name, itf.Zone, offloadStr, itf.IPAddresses)
	}
}
