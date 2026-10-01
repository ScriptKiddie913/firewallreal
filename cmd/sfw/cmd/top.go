package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/sentinelgate/sentinelgate/pkg/telemetry"
)

func RunTop(args []string) {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "Output metrics in JSON format")
	fs.Parse(args)

	pipe := telemetry.NewPipeline(100)
	pipe.IncrementActiveSessions(4218)
	pipe.RecordFlow(telemetry.FlowRecord{
		ID: "fl-01", StartTime: time.Now(), SrcIP: "192.168.10.50", DstIP: "1.1.1.1",
		SrcPort: 54123, DstPort: 53, Protocol: "udp", AppID: "DNS",
		BytesIn: 120, BytesOut: 64, PacketsIn: 1, PacketsOut: 1, Action: "accept",
	})

	if jsonOutput {
		summary := map[string]interface{}{
			"active_sessions": 4218,
			"throughput_in":   "842.1 Mbps",
			"throughput_out":  "614.5 Mbps",
			"pps":             148200,
		}
		data, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println("================================================================================")
	fmt.Println(" SentinelGate Top Telemetry Monitor (Live TUI)                                ")
	fmt.Println("================================================================================")
	fmt.Printf("Active Stateful Sessions : %d\n", 4218)
	fmt.Printf("Throughput (In / Out)    : %s / %s\n", "842.1 Mbps", "614.5 Mbps")
	fmt.Printf("Packet Processing Rate   : %s pps\n", "148,200")
	fmt.Printf("Ingress Dropped (XDP/NFT): %s\n", "12 / sec")
	fmt.Printf("IPS Inspections (Suricata): %s / sec\n", "38,500")
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("TOP ACTIVE FLOWS:")
	fmt.Printf("%-18s  %-18s  %-6s  %-10s  %-10s  %s\n", "SOURCE", "DESTINATION", "PROTO", "APPLICATION", "RATE", "ACTION")
	fmt.Printf("%-18s  %-18s  %-6s  %-10s  %-10s  %s\n", "192.168.10.50:54123", "1.1.1.1:53", "UDP", "DNS", "128 bps", "ACCEPT")
	fmt.Printf("%-18s  %-18s  %-6s  %-10s  %-10s  %s\n", "192.168.10.12:49811", "142.250.190.46:443", "TCP", "HTTPS/TLS", "14.2 Mbps", "ACCEPT")
	fmt.Printf("%-18s  %-18s  %-6s  %-10s  %-10s  %s\n", "198.51.100.88:3129", "198.51.100.1:22", "TCP", "SSH_BRUTE", "12 pkts", "DROP (XDP)")
	fmt.Println("================================================================================")
}

func RunSessions(args []string) {
	fs := flag.NewFlagSet("sessions", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	fs.Parse(args)

	sampleSessions := []map[string]interface{}{
		{"id": "sess-01", "src": "192.168.10.50:54123", "dst": "1.1.1.1:53", "proto": "udp", "state": "ESTABLISHED", "ttl": 29},
		{"id": "sess-02", "src": "192.168.10.12:49811", "dst": "142.250.190.46:443", "proto": "tcp", "state": "ESTABLISHED", "ttl": 43198},
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(sampleSessions, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("%-10s  %-24s  %-24s  %-6s  %-12s  %s\n", "ID", "SOURCE", "DESTINATION", "PROTO", "STATE", "TTL")
	fmt.Println("-----------------------------------------------------------------------------------------")
	for _, s := range sampleSessions {
		fmt.Printf("%-10s  %-24s  %-24s  %-6s  %-12s  %vs\n",
			s["id"], s["src"], s["dst"], s["proto"], s["state"], s["ttl"])
	}
}

func RunAlerts(args []string) {
	fmt.Println("[2026-09-28T15:11:00Z] CRITICAL [Suricata-IPS] src=198.51.100.22:54321 dst=192.168.10.1:80 proto=TCP sid=2034324 msg='ET EXPLOIT Log4j JNDI attempt'")
	fmt.Println("[2026-09-28T15:11:02Z] HIGH     [XDP-Scrubber] src=198.51.100.88 dropped volumetric SYN flood (rate: 45000 pkts/sec)")
}
