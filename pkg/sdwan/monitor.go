// Package sdwan provides SLA monitoring and application path selection across WAN links.
package sdwan

import (
	"sync"
	"time"
)

// LinkMetrics stores SLA quality measurements for a WAN link.
type LinkMetrics struct {
	InterfaceName string        `json:"interface_name"`
	Latency       time.Duration `json:"latency"`
	Jitter        time.Duration `json:"jitter"`
	PacketLossPct float64       `json:"packet_loss_pct"`
	State         string        `json:"state"` // UP, DEGRADED, DOWN
	LastProbed    time.Time     `json:"last_probed"`
}

// SLAPolicy defines quality thresholds required for traffic classes.
type SLAPolicy struct {
	Name            string        `json:"name"` // e.g. "VoIP_SLA", "Web_SLA"
	MaxLatency      time.Duration `json:"max_latency"`
	MaxJitter       time.Duration `json:"max_jitter"`
	MaxLossPct      float64       `json:"max_loss_pct"`
	PreferredLink   string        `json:"preferred_link"`
	SecondaryLink   string        `json:"secondary_link"`
}

// PathSelector evaluates SLA health and decides active WAN exit paths.
type PathSelector struct {
	mu      sync.RWMutex
	links   map[string]*LinkMetrics
	polices map[string]*SLAPolicy
}

// NewPathSelector creates a new SD-WAN path controller.
func NewPathSelector() *PathSelector {
	return &PathSelector{
		links:   make(map[string]*LinkMetrics),
		polices: make(map[string]*SLAPolicy),
	}
}

// UpdateLinkMetrics records fresh probe data from a WAN interface.
func (ps *PathSelector) UpdateLinkMetrics(m LinkMetrics) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	state := "UP"
	if m.PacketLossPct >= 50.0 || m.Latency > 500*time.Millisecond {
		state = "DOWN"
	} else if m.PacketLossPct > 2.0 || m.Latency > 150*time.Millisecond {
		state = "DEGRADED"
	}
	m.State = state
	m.LastProbed = time.Now()

	ps.links[m.InterfaceName] = &m
}

// RegisterSLAPolicy sets an SLA policy definition.
func (ps *PathSelector) RegisterSLAPolicy(p SLAPolicy) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.polices[p.Name] = &p
}

// SelectPath chooses the optimal WAN interface according to real-time SLA metrics.
func (ps *PathSelector) SelectPath(slaName string) (selectedInterface string, reason string) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	policy, ok := ps.polices[slaName]
	if !ok {
		return "eth0", "default WAN route (no SLA policy specified)"
	}

	pref := ps.links[policy.PreferredLink]
	// Check if preferred link meets SLA criteria
	if pref != nil && pref.State == "UP" {
		if pref.Latency <= policy.MaxLatency && pref.PacketLossPct <= policy.MaxLossPct && pref.Jitter <= policy.MaxJitter {
			return policy.PreferredLink, "preferred link meets SLA requirements"
		}
	}

	// Preferred link degraded or down; check secondary
	sec := ps.links[policy.SecondaryLink]
	if sec != nil && sec.State != "DOWN" {
		return policy.SecondaryLink, "failover to secondary link due to preferred link SLA degradation"
	}

	return policy.PreferredLink, "best-effort on preferred link (all candidates degraded)"
}
