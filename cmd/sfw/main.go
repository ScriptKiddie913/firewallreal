// Package main implements the unified CLI / TUI tool sfw for SentinelGate & SentinelFW.
package main

import (
	"fmt"
	"os"

	"github.com/sentinelgate/sentinelgate/cmd/sfw/cmd"
	"github.com/spf13/cobra"
)

var (
	Version = "3.0.0-dev"
	jsonOut bool
)

var rootCmd = &cobra.Command{
	Use:   "sfw",
	Short: "sfw - Unified command-line interface and TUI for SentinelGate and SentinelFW",
	Long: `sfw is the central management and diagnostic utility for SentinelGate NGFW 
appliances and SentinelFW 3.0 endpoint security agents.`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print SentinelGate / SentinelFW version",
	Run: func(cmd *cobra.Command, args []string) {
		if jsonOut {
			fmt.Printf(`{"version":"%s"}`+"\n", Version)
		} else {
			fmt.Printf("SentinelGate / SentinelFW CLI (sfw) version %s\n", Version)
		}
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "Output results in JSON format")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(cmd.PolicyCmd)
	rootCmd.AddCommand(cmd.CommitCmd)
	rootCmd.AddCommand(cmd.ConfirmCmd)
	rootCmd.AddCommand(cmd.RollbackCmd)
	rootCmd.AddCommand(cmd.TuneCmd)
	rootCmd.AddCommand(cmd.RoutesCmd)
	rootCmd.AddCommand(cmd.InterfacesCmd)
	rootCmd.AddCommand(cmd.TopCmd)
	rootCmd.AddCommand(cmd.SessionsCmd)
	rootCmd.AddCommand(cmd.AlertsCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
