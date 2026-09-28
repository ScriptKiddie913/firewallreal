// Package cmd implements the CLI subcommands for the sfw tool.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sentinelgate/sentinelgate/pkg/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	configDir string
	jsonOutput bool
)

// PolicyCmd represents the policy management command group.
var PolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Inspect and manage firewall policies",
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active firewall policies",
	Run: func(cmd *cobra.Command, args []string) {
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
	},
}

var policyCheckCmd = &cobra.Command{
	Use:   "check [file.yaml]",
	Short: "Validate candidate policy syntax and structural integrity",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filePath, err)
			os.Exit(1)
		}

		var candidate config.GatewayConfig
		if err := yaml.Unmarshal(data, &candidate); err != nil {
			fmt.Fprintf(os.Stderr, "YAML parsing error: %v\n", err)
			os.Exit(1)
		}

		if err := candidate.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "[VALIDATION FAILED] %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[VALIDATION SUCCESS] Configuration syntax, zones, and rules are valid.")
	},
}

func init() {
	PolicyCmd.PersistentFlags().StringVar(&configDir, "config-dir", "/etc/sentinelgate", "Configuration state directory")
	PolicyCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	PolicyCmd.AddCommand(policyListCmd)
	PolicyCmd.AddCommand(policyCheckCmd)
}
