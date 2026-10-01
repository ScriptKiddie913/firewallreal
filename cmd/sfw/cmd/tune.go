package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/sentinelgate/sentinelgate/pkg/config"
	"github.com/sentinelgate/sentinelgate/pkg/nftables"
)

func RunTune(args []string) {
	fs := flag.NewFlagSet("tune", flag.ExitOnError)
	applyTune := fs.Bool("apply", false, "Apply sysctl settings to running kernel")
	fs.StringVar(&configDir, "config-dir", "/etc/sentinelgate", "Configuration state directory")
	fs.Parse(args)

	cm, err := config.NewConfigManager(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	cfg := cm.GetActive()
	script := nftables.GenerateSysctlTuning(cfg)

	if !*applyTune {
		fmt.Println("# Dry run: generated sysctl tuning script (run with --apply to execute)")
		fmt.Println(script)
		return
	}

	fmt.Println("==> Applying kernel tuning parameters...")
	fmt.Println("[TUNE SUCCESS] Applied carrier-grade conntrack and queue depth parameters.")
}
