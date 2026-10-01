// Package nftables compiles declarative GatewayConfig into atomic, stateful nftables rulesets.
package nftables

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sentinelgate/sentinelgate/pkg/config"
)

// Compiler translates a declarative GatewayConfig into an atomic nftables script.
type Compiler struct {
	cfg *config.GatewayConfig
}

// NewCompiler creates a new nftables compiler instance.
func NewCompiler(cfg *config.GatewayConfig) *Compiler {
	return &Compiler{cfg: cfg}
}

// Compile generates the complete atomic nftables script string.
func (c *Compiler) Compile() (string, error) {
	var b bytes.Buffer

	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# SentinelGate Atomic Ruleset Compiler\n")
	b.WriteString(fmt.Sprintf("# Generated: %s\n\n", c.cfg.Version))

	// Run policy optimizer analysis
	opt := NewPolicyOptimizer(c.cfg)
	diags := opt.Analyze()
	if len(diags) > 0 {
		b.WriteString("# --- Policy Diagnostics & Warnings ---\n")
		for _, d := range diags {
			b.WriteString(fmt.Sprintf("# [%s] Policy %d (%s): %s\n", d.Severity, d.PolicyID, d.RuleName, d.Message))
		}
		b.WriteString("# ------------------------------------\n\n")
	}

	// Flush and recreate the sentinelgate table
	b.WriteString("flush table inet sentinelgate\n")
	b.WriteString("delete table inet sentinelgate\n")
	b.WriteString("add table inet sentinelgate {\n")

	// 1. Flowtable definition for established L4 offload (T1/T2 fast path)
	if c.cfg.System.FlowtableOffload {
		var offloadDevices []string
		for _, itf := range c.cfg.Interfaces {
			if itf.Offload {
				offloadDevices = append(offloadDevices, itf.Name)
			}
		}
		if len(offloadDevices) > 0 {
			b.WriteString(fmt.Sprintf("\tflowtable ft {\n\t\thook ingress priority -100\n\t\tdevices = { %s }\n\t}\n\n",
				strings.Join(offloadDevices, ", ")))
		}
	}

	// 2. Address Group Sets (O(1) interval sets, IPv4 and IPv6)
	for _, ag := range c.cfg.Addresses {
		setName4 := fmt.Sprintf("ag_%s", sanitizeName(ag.Name))
		setName6 := fmt.Sprintf("ag6_%s", sanitizeName(ag.Name))
		var v4Members, v6Members []string
		for _, m := range ag.Members {
			if strings.Contains(m, ":") {
				v6Members = append(v6Members, m)
			} else {
				v4Members = append(v4Members, m)
			}
		}
		b.WriteString(fmt.Sprintf("\tset %s {\n\t\ttype ipv4_addr\n\t\tflags interval\n", setName4))
		if len(v4Members) > 0 {
			b.WriteString(fmt.Sprintf("\t\telements = { %s }\n", strings.Join(v4Members, ", ")))
		}
		b.WriteString("\t}\n")
		b.WriteString(fmt.Sprintf("\tset %s {\n\t\ttype ipv6_addr\n\t\tflags interval\n", setName6))
		if len(v6Members) > 0 {
			b.WriteString(fmt.Sprintf("\t\telements = { %s }\n", strings.Join(v6Members, ", ")))
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("\n")

	// 3. Base Chains
	// --- Ingress / Prerouting (Raw & DNAT) ---
	b.WriteString("\tchain prerouting {\n")
	b.WriteString("\t\ttype filter hook prerouting priority -300; policy accept;\n")
	// Ingress XDP handles bogons; here we can add raw drop hooks
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain nat_prerouting {\n")
	b.WriteString("\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	// Compile DNAT / Port forwarding rules
	for _, pol := range c.cfg.Policies {
		if !pol.Enabled || pol.NAT == nil || pol.NAT.Type != config.NATDNAT {
			continue
		}
		if pol.NAT.TargetIP != "" {
			portSpec := ""
			if pol.NAT.TargetPort > 0 {
				portSpec = fmt.Sprintf(":%d", pol.NAT.TargetPort)
			}
			b.WriteString(fmt.Sprintf("\t\t# DNAT Policy %d: %s\n", pol.ID, pol.Name))
			b.WriteString(fmt.Sprintf("\t\tdnat to %s%s\n", pol.NAT.TargetIP, portSpec))
		}
	}
	b.WriteString("\t}\n\n")

	// --- Input Chain (Appliance Local Delivery) ---
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority 0; policy drop;\n")
	b.WriteString("\t\t# Conntrack established & related accept\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n")
	b.WriteString("\t\t# Loopback interface accept\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	b.WriteString("\t\t# ICMP rate limiting\n")
	b.WriteString("\t\tip protocol icmp icmp type echo-request limit rate 10/second accept\n")
	b.WriteString("\t\tip6 nexthdr ipv6-icmp accept\n")
	b.WriteString("\t\t# Management Plane Ports (mTLS 8443, SSH 22) restricted to local and mgmt interfaces\n")
	b.WriteString("\t\tiifname \"lo\" tcp dport { 22, 8443 } accept\n")
	b.WriteString("\t\tiifname \"mgmt0\" tcp dport { 22, 8443 } accept\n")
	b.WriteString("\t\t# DHCP server port for local LAN interfaces\n")
	b.WriteString("\t\tudp dport 67 accept\n")
	b.WriteString("\t}\n\n")

	// --- Forward Chain (Transit Traffic & Flowtable Jump) ---
	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority 0; policy drop;\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n\n")

	// Zone-pair jumps
	zonePairs := c.buildZonePairs()
	for zp, itfPair := range zonePairs {
		chainName := fmt.Sprintf("zp_%s", zp)
		b.WriteString(fmt.Sprintf("\t\tiifname \"%s\" oifname \"%s\" jump %s\n", itfPair.InItf, itfPair.OutItf, chainName))
	}
	b.WriteString("\t}\n\n")

	// --- Output Chain (Appliance Generated Egress) ---
	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority 0; policy accept;\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n")
	b.WriteString("\t\toifname \"lo\" accept\n")
	b.WriteString("\t}\n\n")

	// --- Postrouting / SNAT Chain ---
	b.WriteString("\tchain nat_postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	for _, pol := range c.cfg.Policies {
		if !pol.Enabled || pol.NAT == nil {
			continue
		}
		if pol.NAT.Type == config.NATMasquerade {
			outItf := c.getZoneInterface(pol.DstZone)
			if outItf != "" {
				b.WriteString(fmt.Sprintf("\t\t# Masquerade Policy %d: %s\n", pol.ID, pol.Name))
				b.WriteString(fmt.Sprintf("\t\toifname \"%s\" masquerade\n", outItf))
			}
		} else if pol.NAT.Type == config.NATSNAT && pol.NAT.TargetIP != "" {
			outItf := c.getZoneInterface(pol.DstZone)
			if outItf != "" {
				b.WriteString(fmt.Sprintf("\t\t# SNAT Policy %d: %s\n", pol.ID, pol.Name))
				b.WriteString(fmt.Sprintf("\t\toifname \"%s\" snat to %s\n", outItf, pol.NAT.TargetIP))
			}
		}
	}
	b.WriteString("\t}\n\n")

	// 4. Zone-Pair Filter Chains
	for zp := range zonePairs {
		chainName := fmt.Sprintf("zp_%s", zp)
		b.WriteString(fmt.Sprintf("\tchain %s {\n", chainName))
		for _, pol := range c.cfg.Policies {
			if !pol.Enabled {
				continue
			}
			pairKey := fmt.Sprintf("%s_%s", pol.SrcZone, pol.DstZone)
			if pairKey != zp && !(pol.SrcZone == "any" || pol.DstZone == "any") {
				continue
			}
			c.compilePolicyRule(&b, pol)
		}
		b.WriteString("\t}\n\n")
	}

	b.WriteString("}\n")
	return b.String(), nil
}

type zoneInterfacePair struct {
	InItf  string
	OutItf string
}

func (c *Compiler) buildZonePairs() map[string]zoneInterfacePair {
	pairs := make(map[string]zoneInterfacePair)
	for _, inItf := range c.cfg.Interfaces {
		for _, outItf := range c.cfg.Interfaces {
			if inItf.Name == outItf.Name {
				continue
			}
			key := fmt.Sprintf("%s_%s", inItf.Zone, outItf.Zone)
			pairs[key] = zoneInterfacePair{
				InItf:  inItf.Name,
				OutItf: outItf.Name,
			}
		}
	}
	return pairs
}

func (c *Compiler) getZoneInterface(zone string) string {
	for _, itf := range c.cfg.Interfaces {
		if itf.Zone == zone {
			return itf.Name
		}
	}
	return ""
}

func (c *Compiler) compilePolicyRule(b *bytes.Buffer, pol config.PolicyRule) {
	b.WriteString(fmt.Sprintf("\t\t# Rule %d: %s\n", pol.ID, pol.Name))

	var clauses []string

	// Source Addresses
	if len(pol.SrcAddr) > 0 && pol.SrcAddr[0] != "any" {
		clauses = append(clauses, fmt.Sprintf("ip saddr @ag_%s", sanitizeName(pol.SrcAddr[0])))
	}

	// Destination Addresses
	if len(pol.DstAddr) > 0 && pol.DstAddr[0] != "any" {
		clauses = append(clauses, fmt.Sprintf("ip daddr @ag_%s", sanitizeName(pol.DstAddr[0])))
	}

	// L4 Services
	if len(pol.Services) > 0 && pol.Services[0] != "any" {
		svc := c.findService(pol.Services[0])
		if svc != nil {
			if svc.Protocol == "tcp" || svc.Protocol == "udp" {
				if svc.Ports != "" {
					clauses = append(clauses, fmt.Sprintf("%s dport { %s }", svc.Protocol, svc.Ports))
				} else {
					clauses = append(clauses, fmt.Sprintf("ip protocol %s", svc.Protocol))
				}
			} else if svc.Protocol == "icmp" {
				clauses = append(clauses, "ip protocol icmp")
			}
		}
	}

	// Inspection Profile (NFQUEUE multi-queue distribution to Suricata)
	if pol.Inspection.IPSProfile != "" {
		clauses = append(clauses, "queue num 0-3 bypass")
	}

	// Logging
	if pol.LogTraffic {
		clauses = append(clauses, fmt.Sprintf("log prefix \"[SGW-POL-%d] \"", pol.ID))
	}

	// Final Action & Fastpath Offload Eligibility
	switch pol.Action {
	case config.ActionAccept:
		// Eligible for hardware / flowtable fastpath only if NO deep proxy inspection is requested
		if c.cfg.System.FlowtableOffload && pol.Inspection.IPSProfile == "" && !pol.Inspection.AVScan && !pol.Inspection.TLSInspect && !pol.Inspection.DLPEnabled && pol.Inspection.WebFilter == "" {
			clauses = append(clauses, "flow add @ft counter accept")
		} else {
			clauses = append(clauses, "counter accept")
		}
	case config.ActionDeny:
		clauses = append(clauses, "counter drop")
	case config.ActionReject:
		clauses = append(clauses, "counter reject")
	case config.ActionRateLimit:
		clauses = append(clauses, "limit rate 100/second counter accept")
	case config.ActionQuarantine, config.ActionRedirect, config.ActionTarpit, config.ActionDecoy:
		clauses = append(clauses, "counter drop")
	case config.ActionLog:
		clauses = append(clauses, "log prefix \"[SGW-LOG] \" counter accept")
	default:
		clauses = append(clauses, "counter drop")
	}

	b.WriteString(fmt.Sprintf("\t\t%s\n", strings.Join(clauses, " ")))
}

func (c *Compiler) findService(name string) *config.Service {
	for _, s := range c.cfg.Services {
		if s.Name == name {
			return &s
		}
	}
	return nil
}

func sanitizeName(n string) string {
	r := strings.ReplaceAll(n, "-", "_")
	r = strings.ReplaceAll(r, " ", "_")
	return strings.ToLower(r)
}

// GenerateSysctlTuning produces the Linux kernel conntrack and networking tuning commands.
func GenerateSysctlTuning(cfg *config.GatewayConfig) string {
	ctMax := cfg.System.ConntrackMax
	if ctMax <= 0 {
		ctMax = 1048576
	}
	hashSize := ctMax / 4

	return fmt.Sprintf(`#!/usr/bin/env bash
# SentinelGate System & Conntrack Auto-Tuner (T1/T2 Optimization)
set -e

echo "==> Applying SentinelGate Carrier-Grade Sysctl Settings..."
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.netfilter.nf_conntrack_max=%d
echo %d > /sys/module/nf_conntrack/parameters/hashsize

# Socket buffer & queue depth optimization
sysctl -w net.core.rmem_max=67108864
sysctl -w net.core.wmem_max=67108864
sysctl -w net.core.rmem_default=33554432
sysctl -w net.core.wmem_default=33554432
sysctl -w net.core.netdev_max_backlog=100000
sysctl -w net.core.somaxconn=65535

# Conntrack aggressive session timeout tuning
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=43200
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_syn_recv=30
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=30
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=30

echo "==> Conntrack and Network Tuning Complete."
`, ctMax, hashSize)
}
