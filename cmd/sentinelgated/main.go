// Package main implements the entrypoint for sentinelgated,
// the SentinelGate Next-Generation Firewall control daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	// Version is set during build linking.
	Version = "3.0.0-dev"
)

func main() {
	configPath := flag.String("config", "/etc/sentinelgate/sentinelgate.yaml", "Path to declarative configuration file")
	socketPath := flag.String("socket", "/run/sentinelgate.sock", "Path to local UNIX domain management socket")
	listenAddr := flag.String("listen", ":8443", "Management mTLS HTTPS / gRPC listen address")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SentinelGate Management Daemon (sentinelgated) version %s\n", Version)
		os.Exit(0)
	}

	log.Printf("[INFO] Initializing SentinelGate NGFW Daemon v%s...", Version)
	log.Printf("[INFO] Config path: %s", *configPath)
	log.Printf("[INFO] Local UNIX socket: %s", *socketPath)
	log.Printf("[INFO] Remote Management socket: %s", *listenAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Received signal %v, initiating graceful shutdown...", sig)
		cancel()
	}()

	<-ctx.Done()
	log.Println("[INFO] SentinelGate daemon stopped cleanly.")
}
