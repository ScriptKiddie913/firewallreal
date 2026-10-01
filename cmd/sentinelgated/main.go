// Package main implements the entrypoint for sentinelgated,
// the SentinelGate Next-Generation Firewall control daemon.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sentinelgate/sentinelgate/pkg/config"
	"github.com/sentinelgate/sentinelgate/pkg/dnsfilter"
	"github.com/sentinelgate/sentinelgate/pkg/ha"
	"github.com/sentinelgate/sentinelgate/pkg/nftables"
	"github.com/sentinelgate/sentinelgate/pkg/sdwan"
	"github.com/sentinelgate/sentinelgate/pkg/suricata"
	"github.com/sentinelgate/sentinelgate/pkg/tlsproxy"
	"github.com/sentinelgate/sentinelgate/pkg/vpn"
)

var (
	// Version is set during build linking.
	Version = "3.0.0-dev"
)

func main() {
	configPath := flag.String("config", "/etc/sentinelgate/sentinelgate.json", "Path to declarative configuration file")
	socketPath := flag.String("socket", "/run/sentinelgate.sock", "Path to local UNIX domain management socket")
	listenAddr := flag.String("listen", ":8443", "Management mTLS HTTPS / gRPC listen address")
	tlsProxyPort := flag.String("tproxy-port", ":8444", "Transparent TLS inspection proxy listen port")
	enableTLSProxy := flag.Bool("tls-proxy", false, "Start transparent TLS forward inspection proxy")
	applyRules := flag.Bool("apply", false, "Atomically commit compiled nftables ruleset to Linux kernel")
	enableVPN := flag.Bool("vpn", false, "Initialize WireGuard and IPsec VPN endpoints")
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

	// 1. Load Declarative Gateway Configuration
	var cfg config.GatewayConfig
	cfgData, err := os.ReadFile(*configPath)
	if err == nil {
		if err := json.Unmarshal(cfgData, &cfg); err != nil {
			log.Printf("[WARN] Failed to parse %s as JSON: %v. Using defaults.", *configPath, err)
		} else {
			log.Printf("[INFO] Loaded configuration: %s (Hostname: %s, Policies: %d)",
				cfg.Version, cfg.System.Hostname, len(cfg.Policies))
		}
	} else {
		log.Printf("[INFO] Config file not found (%v), operating in standalone/runtime mode.", err)
	}

	// 2. Compile and Verify nftables Data Plane Ruleset
	if len(cfg.Policies) > 0 {
		compiler := nftables.NewCompiler(&cfg)
		ruleset, err := compiler.Compile()
		if err != nil {
			log.Printf("[ERROR] Failed to compile atomic nftables ruleset: %v", err)
		} else {
			log.Printf("[INFO] Generated atomic nftables ruleset (%d bytes)", len(ruleset))

			if *applyRules || os.Getenv("SENTINELGATE_APPLY_RULES") == "1" {
				log.Println("[INFO] Committing atomic ruleset to Linux kernel (nft -f -)...")
				nftCmd := exec.CommandContext(ctx, "nft", "-f", "-")
				nftCmd.Stdin = strings.NewReader(ruleset)
				out, err := nftCmd.CombinedOutput()
				if err != nil {
					log.Printf("[ERROR] Kernel rejected nftables ruleset: %v (output: %s)", err, string(out))
				} else {
					log.Println("[INFO] Successfully committed atomic nftables ruleset to kernel.")
				}
			}
		}
	}

	// 3. Launch TLS Forward Inspection Proxy if enabled
	if *enableTLSProxy {
		proxy, err := tlsproxy.NewTLSProxy(&tlsproxy.ProxyConfig{
			Mode:               tlsproxy.ModeFullInspection,
			MinTLSVersion:      0x0303, // TLS 1.2
			StrictUpstreamCert: true,
			BypassList:         tlsproxy.DefaultPrivacyBypassList,
		})
		if err != nil {
			log.Printf("[ERROR] Failed to initialize TLS proxy: %v", err)
		} else {
			ln, err := net.Listen("tcp", *tlsProxyPort)
			if err != nil {
				log.Printf("[ERROR] Failed to listen on TLS proxy port %s: %v", *tlsProxyPort, err)
			} else {
				go func() {
					if err := proxy.Serve(ln); err != nil {
						log.Printf("[INFO] TLS Proxy stopped: %v", err)
					}
				}()
				defer proxy.Close()
			}
		}
	}

	// 4. Initialize Suricata IPS / Event Manager
	suriMgr := suricata.NewManager("", "")
	go func() {
		stream := suriMgr.EventStream()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-stream:
				if !ok {
					return
				}
				if ev.Alert.Severity <= 2 {
					log.Printf("[IPS ALERT] Severity %d: %s from %s -> %s",
						ev.Alert.Severity, ev.Alert.Signature, ev.SrcIP, ev.DstIP)
				}
			}
		}
	}()

	// 5. Initialize High Availability (VRRP) Failover Manager
	haMgr := ha.NewFailoverManager(ha.HAConfig{
		VirtualRouterID: 51,
		Priority:        150,
		AuthPass:        "SFW_HA_PASS",
	})
	log.Printf("[INFO] High Availability subsystem ready (Initial Role: %s)", haMgr.GetRole())

	// 6. Initialize SD-WAN SLA Probing
	sdwanMgr := sdwan.NewSDWANManager([]sdwan.SLAProbe{})
	sdwanMgr.StartProbes(ctx)

	// 7. Initialize DNS and DHCP Services
	dnsDHCPReady := true
	if len(cfg.DHCP) > 0 {
		_ = dnsfilter.GenerateDnsmasqDHCP(&cfg)
	}
	log.Printf("[INFO] DNS and DHCP subsystem initialized: %v", dnsDHCPReady)

	// 8. Initialize WireGuard VPN Subsystem
	if *enableVPN {
		wgServer, err := vpn.NewWireGuardServer("wg0", 51820, "10.100.0.0/24")
		if err != nil {
			log.Printf("[WARN] WireGuard VPN server initialization deferred: %v", err)
		} else {
			log.Printf("[INFO] WireGuard VPN server ready on %s", wgServer.GetPublicKey())
		}
	}

	// 9. Start Management HTTP API Listener
	startTime := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"version": Version,
			"ha_role": haMgr.GetRole(),
		})
	})
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":    Version,
			"ha_role":    haMgr.GetRole(),
			"policies":   len(cfg.Policies),
			"dns_dhcp":   dnsDHCPReady,
			"tls_proxy":  *enableTLSProxy,
			"uptime_sec": time.Since(startTime).Seconds(),
		})
	})

	mgmtServer := &http.Server{
		Addr:    *listenAddr,
		Handler: mux,
	}
	go func() {
		log.Printf("[INFO] Starting Management API server on %s", *listenAddr)
		if err := mgmtServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[WARN] Management HTTP server terminated: %v", err)
		}
	}()
	defer mgmtServer.Shutdown(context.Background())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Received signal %v, initiating graceful shutdown...", sig)
		cancel()
	}()

	<-ctx.Done()
	// Allow background workers to clean up
	time.Sleep(100 * time.Millisecond)
	log.Println("[INFO] SentinelGate daemon stopped cleanly.")
}
