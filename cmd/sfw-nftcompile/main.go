// Package main provides the command-line interface to compile declarative GatewayConfig JSON
// into atomic, stateful nftables scripts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sentinelgate/sentinelgate/pkg/config"
	"github.com/sentinelgate/sentinelgate/pkg/nftables"
)

func main() {
	inputFile := flag.String("in", "", "Input GatewayConfig JSON file (default: stdin)")
	outputFile := flag.String("out", "", "Output nftables script file (default: stdout)")
	validateOnly := flag.Bool("validate", false, "Only validate configuration without printing ruleset")
	flag.Parse()

	var inputData []byte
	var err error

	if *inputFile != "" {
		inputData, err = os.ReadFile(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file %s: %v\n", *inputFile, err)
			os.Exit(1)
		}
	} else {
		inputData, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	var cfg config.GatewayConfig
	if err := json.Unmarshal(inputData, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse JSON config: %v\n", err)
		os.Exit(2)
	}

	if *validateOnly {
		fmt.Println("Config syntax is valid.")
		os.Exit(0)
	}

	compiler := nftables.NewCompiler(&cfg)
	ruleset, err := compiler.Compile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Compilation error: %v\n", err)
		os.Exit(3)
	}

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(ruleset), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output to %s: %v\n", *outputFile, err)
			os.Exit(4)
		}
	} else {
		fmt.Print(ruleset)
	}
}
