package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/sentinelgate/sentinelgate/pkg/config"
	"github.com/sentinelgate/sentinelgate/pkg/nftables"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	confirmTimeout time.Duration
)

// CommitCmd applies candidate configuration with commit-confirm safety.
var CommitCmd = &cobra.Command{
	Use:   "commit [candidate.yaml]",
	Short: "Commit candidate configuration to active ruleset with auto-rollback guard",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cm, err := config.NewConfigManager(configDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if len(args) == 1 {
			data, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading candidate file: %v\n", err)
				os.Exit(1)
			}
			var cand config.GatewayConfig
			if err := yaml.Unmarshal(data, &cand); err != nil {
				fmt.Fprintf(os.Stderr, "YAML error: %v\n", err)
				os.Exit(1)
			}
			if err := cm.SetCandidate(&cand); err != nil {
				fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
				os.Exit(1)
			}
		}

		cand := cm.GetCandidate()
		if cand == nil {
			fmt.Println("No candidate configuration present to commit.")
			return
		}

		// Compile to nftables ruleset
		compiler := nftables.NewCompiler(cand)
		nftScript, err := compiler.Compile()
		if err != nil {
			fmt.Fprintf(os.Stderr, "nftables compile error: %v\n", err)
			os.Exit(1)
		}

		// Commit with confirmation timer
		h, err := cm.Commit(confirmTimeout, func() {
			fmt.Println("\n[AUTO-ROLLBACK TRIGGERED] Confirmation timeout expired. Configuration rolled back.")
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Commit error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[COMMIT SUCCESS] Revision: %s\n", h[:12])
		fmt.Printf("Compiled %d bytes of atomic nftables ruleset.\n", len(nftScript))
		if confirmTimeout > 0 {
			fmt.Printf("[COMMIT-CONFIRM ACTIVE] Must run 'sfw confirm' within %v or state will automatically rollback.\n", confirmTimeout)
		}
	},
}

// ConfirmCmd confirms the pending commit.
var ConfirmCmd = &cobra.Command{
	Use:   "confirm",
	Short: "Confirm pending configuration commit and cancel rollback timer",
	Run: func(cmd *cobra.Command, args []string) {
		cm, err := config.NewConfigManager(configDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := cm.Confirm(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[CONFIRM SUCCESS] Configuration locked into active state. Rollback timer cancelled.")
	},
}

// RollbackCmd reverts configuration to previous state.
var RollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Immediately rollback to previous configuration state",
	Run: func(cmd *cobra.Command, args []string) {
		cm, err := config.NewConfigManager(configDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := cm.Rollback(); err != nil {
			fmt.Fprintf(os.Stderr, "Rollback error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[ROLLBACK SUCCESS] Configuration successfully restored to previous state.")
	},
}

func init() {
	CommitCmd.Flags().DurationVar(&confirmTimeout, "confirm", 10*time.Minute, "Commit-confirm auto-rollback countdown")
}
