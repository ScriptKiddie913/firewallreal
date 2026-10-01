// Package nftables implements policy validation, optimization, and compilation.
package nftables

import (
	"fmt"
	"strings"

	"github.com/sentinelgate/sentinelgate/pkg/config"
)

// DiagnosticSeverity indicates the severity of a policy finding.
type DiagnosticSeverity string

const (
	SeverityError   DiagnosticSeverity = "ERROR"
	SeverityWarning DiagnosticSeverity = "WARNING"
	SeverityInfo    DiagnosticSeverity = "INFO"
)

// PolicyDiagnostic contains analysis findings from the policy optimizer.
type PolicyDiagnostic struct {
	PolicyID int                `json:"policy_id"`
	RuleName string             `json:"rule_name"`
	Severity DiagnosticSeverity `json:"severity"`
	Message  string             `json:"message"`
}

// PolicyOptimizer analyzes the declarative policy ruleset for conflicts,
// shadowed rules, duplicate entries, and missing dependencies.
type PolicyOptimizer struct {
	cfg *config.GatewayConfig
}

// NewPolicyOptimizer creates a new policy optimizer instance.
func NewPolicyOptimizer(cfg *config.GatewayConfig) *CompilerOptimizer {
	return &CompilerOptimizer{cfg: cfg}
}

type CompilerOptimizer struct {
	cfg *config.GatewayConfig
}

// Analyze runs the semantic validation and conflict detection passes.
func (opt *CompilerOptimizer) Analyze() []PolicyDiagnostic {
	var diags []PolicyDiagnostic
	if opt.cfg == nil || len(opt.cfg.Policies) == 0 {
		return diags
	}

	knownZones := make(map[string]bool)
	knownZones["any"] = true
	for _, itf := range opt.cfg.Interfaces {
		if itf.Zone != "" {
			knownZones[itf.Zone] = true
		}
	}

	knownAddresses := make(map[string]bool)
	knownAddresses["any"] = true
	for _, addr := range opt.cfg.Addresses {
		knownAddresses[addr.Name] = true
	}

	knownServices := make(map[string]bool)
	knownServices["any"] = true
	for _, svc := range opt.cfg.Services {
		knownServices[svc.Name] = true
	}

	seenPolicies := make(map[string]int) // signature -> policy ID

	for i, pol := range opt.cfg.Policies {
		if !pol.Enabled {
			diags = append(diags, PolicyDiagnostic{
				PolicyID: pol.ID,
				RuleName: pol.Name,
				Severity: SeverityInfo,
				Message:  "Policy rule is disabled; will not be compiled to dataplane.",
			})
			continue
		}

		// 1. Dependency validation: zones
		if !knownZones[pol.SrcZone] {
			diags = append(diags, PolicyDiagnostic{
				PolicyID: pol.ID,
				RuleName: pol.Name,
				Severity: SeverityError,
				Message:  fmt.Sprintf("Source zone '%s' is not bound to any interface.", pol.SrcZone),
			})
		}
		if !knownZones[pol.DstZone] {
			diags = append(diags, PolicyDiagnostic{
				PolicyID: pol.ID,
				RuleName: pol.Name,
				Severity: SeverityError,
				Message:  fmt.Sprintf("Destination zone '%s' is not bound to any interface.", pol.DstZone),
			})
		}

		// 2. Address object validation
		for _, sa := range pol.SrcAddr {
			if !knownAddresses[sa] {
				diags = append(diags, PolicyDiagnostic{
					PolicyID: pol.ID,
					RuleName: pol.Name,
					Severity: SeverityError,
					Message:  fmt.Sprintf("Source address group '%s' is undefined.", sa),
				})
			}
		}
		for _, da := range pol.DstAddr {
			if !knownAddresses[da] {
				diags = append(diags, PolicyDiagnostic{
					PolicyID: pol.ID,
					RuleName: pol.Name,
					Severity: SeverityError,
					Message:  fmt.Sprintf("Destination address group '%s' is undefined.", da),
				})
			}
		}

		// 3. Service object validation
		for _, svc := range pol.Services {
			if !knownServices[svc] {
				diags = append(diags, PolicyDiagnostic{
					PolicyID: pol.ID,
					RuleName: pol.Name,
					Severity: SeverityWarning,
					Message:  fmt.Sprintf("Service object '%s' is not predefined in configuration.", svc),
				})
			}
		}

		// 4. Duplicate rule detection
		sig := fmt.Sprintf("%s|%s|%s|%s|%s",
			pol.SrcZone, pol.DstZone,
			strings.Join(pol.SrcAddr, ","),
			strings.Join(pol.DstAddr, ","),
			strings.Join(pol.Services, ","),
		)
		if firstID, exists := seenPolicies[sig]; exists {
			diags = append(diags, PolicyDiagnostic{
				PolicyID: pol.ID,
				RuleName: pol.Name,
				Severity: SeverityWarning,
				Message:  fmt.Sprintf("Duplicate rule definition: identical match criteria to Policy ID %d.", firstID),
			})
		} else {
			seenPolicies[sig] = pol.ID
		}

		// 5. Shadowed rule detection: if a previous rule had 'any' in same zone pair with universal match
		for j := 0; j < i; j++ {
			prev := opt.cfg.Policies[j]
			if !prev.Enabled {
				continue
			}
			if (prev.SrcZone == pol.SrcZone || prev.SrcZone == "any") &&
				(prev.DstZone == pol.DstZone || prev.DstZone == "any") &&
				isUniversal(prev.SrcAddr) && isUniversal(prev.DstAddr) && isUniversal(prev.Services) {
				diags = append(diags, PolicyDiagnostic{
					PolicyID: pol.ID,
					RuleName: pol.Name,
					Severity: SeverityWarning,
					Message:  fmt.Sprintf("Rule is shadowed by Policy ID %d ('%s') which matches all traffic earlier.", prev.ID, prev.Name),
				})
				break
			}
		}
	}

	return diags
}

func isUniversal(items []string) bool {
	if len(items) == 0 {
		return true
	}
	for _, item := range items {
		if item == "any" || item == "0.0.0.0/0" || item == "*" {
			return true
		}
	}
	return false
}
