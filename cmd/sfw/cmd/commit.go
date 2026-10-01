package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sentinelgate/sentinelgate/pkg/config"
	"github.com/sentinelgate/sentinelgate/pkg/nftables"
)

func RunCommit(args []string) {
	fs := flag.NewFlagSet("commit", flag.ExitOnError)
	confirmTimeout := fs.Duration("confirm", 10*time.Minute, "Commit-confirm auto-rollback countdown")
	fs.StringVar(&configDir, "config-dir", "/etc/sentinelgate", "Configuration state directory")
	fs.Parse(args)

	cm, err := config.NewConfigManager(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	remaining := fs.Args()
	if len(remaining) == 1 {
		data, err := os.ReadFile(remaining[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading candidate file: %v\n", err)
			os.Exit(1)
		}
		var cand config.GatewayConfig
		if err := json.Unmarshal(data, &cand); err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
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

	compiler := nftables.NewCompiler(cand)
	nftScript, err := compiler.Compile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nftables compile error: %v\n", err)
		os.Exit(1)
	}

	h, err := cm.Commit(*confirmTimeout, func() {
		fmt.Println("\n[AUTO-ROLLBACK TRIGGERED] Confirmation timeout expired. Configuration rolled back.")
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Commit error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[COMMIT SUCCESS] Revision: %s\n", h[:12])
	fmt.Printf("Compiled %d bytes of atomic nftables ruleset.\n", len(nftScript))
	if *confirmTimeout > 0 {
		fmt.Printf("[COMMIT-CONFIRM ACTIVE] Must run 'sfw confirm' within %v or state will automatically rollback.\n", *confirmTimeout)
	}
}

func RunConfirm(args []string) {
	fs := flag.NewFlagSet("confirm", flag.ExitOnError)
	fs.StringVar(&configDir, "config-dir", "/etc/sentinelgate", "Configuration state directory")
	fs.Parse(args)

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
}

func RunRollback(args []string) {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	fs.StringVar(&configDir, "config-dir", "/etc/sentinelgate", "Configuration state directory")
	fs.Parse(args)

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
}
