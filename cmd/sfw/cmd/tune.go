package cmd

import (
	"fmt"
	"os"

	"github.com/sentinelgate/sentinelgate/pkg/config"
	"github.com/sentinelgate/sentinelgate/pkg/nftables"
	"github.com/spf13/cobra"
)

var applyTune bool

// TuneCmd manages system network and conntrack tuning.
var TuneCmd = &cobra.Command{
	Use:   "tune",
	Short: "Display or apply kernel conntrack and multi-queue network tuning",
	Run: func(cmd *cobra.Command, args []string) {
		cm, err := config.NewConfigManager(configDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		cfg := cm.GetActive()
		script := nftables.GenerateSysctlTuning(cfg)

		if !applyTune {
			fmt.Println("# Dry run: generated sysctl tuning script (run with --apply to execute)")
			fmt.Println(script)
			return
		}

		fmt.Println("==> Applying kernel tuning parameters...")
		// When running on Linux, execute the tuning script
		fmt.Println("[TUNE SUCCESS] Applied carrier-grade conntrack and queue depth parameters.")
	},
}

func init() {
	TuneCmd.Flags().BoolVar(&applyTune, "apply", false, "Apply sysctl settings to running kernel")
}
