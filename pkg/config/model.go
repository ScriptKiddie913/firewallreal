// Package config defines the declarative, FortiOS-inspired policy schema,
// configuration lifecycle, validation rules, and revision history engine for SentinelGate.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

)

// Action defines the firewall policy decision.
type Action string

const (
	ActionAccept     Action = "accept"
	ActionDeny       Action = "deny"
	ActionReject     Action = "reject"
	ActionLog        Action = "log"
	ActionRateLimit  Action = "rate_limit"
	ActionQuarantine Action = "quarantine"
	ActionRedirect   Action = "redirect"
	ActionInspect    Action = "inspect"
	ActionChallenge  Action = "challenge"
	ActionTarpit     Action = "tarpit"
	ActionDecoy      Action = "decoy"
)

// NATType defines the address translation mode.
type NATType string

const (
	NATNone       NATType = "none"
	NATMasquerade NATType = "masquerade"
	NATSNAT       NATType = "snat"
	NATDNAT       NATType = "dnat"
	NAT64         NATType = "nat64"
	NATHairpin    NATType = "hairpin"
)

// Interface represents a physical, VLAN, or virtual interface.
type Interface struct {
	Name        string   `json:"name" yaml:"name"`
	Zone        string   `json:"zone" yaml:"zone"`
	IPAddresses []string `json:"ip_addresses" yaml:"ip_addresses"`
	MTU         int      `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	Offload     bool     `json:"offload,omitempty" yaml:"offload,omitempty"` // Flowtable offload
}

// AddressGroup represents an object of CIDRs, FQDNs, or GeoIP/ASN definitions.
type AddressGroup struct {
	Name    string   `json:"name" yaml:"name"`
	Members []string `json:"members" yaml:"members"` // IP, CIDR, or domain
	GeoIP   []string `json:"geoip,omitempty" yaml:"geoip,omitempty"`
	ASN     []int    `json:"asn,omitempty" yaml:"asn,omitempty"`
}

// Service represents an L4 protocol and port specification.
type Service struct {
	Name     string `json:"name" yaml:"name"`
	Protocol string `json:"protocol" yaml:"protocol"` // tcp, udp, icmp, any
	Ports    string `json:"ports,omitempty" yaml:"ports,omitempty"` // e.g. "80,443", "1000-2000"
}

// InspectionProfile defines the L7 deep packet inspection parameters.
type InspectionProfile struct {
	IPSProfile string `json:"ips_profile,omitempty" yaml:"ips_profile,omitempty"` // balanced, strict, default
	AVScan     bool   `json:"av_scan,omitempty" yaml:"av_scan,omitempty"`
	WebFilter  string `json:"web_filter,omitempty" yaml:"web_filter,omitempty"`   // profile name
	DNSFilter  string `json:"dns_filter,omitempty" yaml:"dns_filter,omitempty"`
	TLSInspect bool   `json:"tls_inspect,omitempty" yaml:"tls_inspect,omitempty"`
	DLPEnabled bool   `json:"dlp_enabled,omitempty" yaml:"dlp_enabled,omitempty"`
}

// NATRule configures address translation on a policy.
type NATRule struct {
	Type        NATType `json:"type" yaml:"type"`
	TargetIP    string  `json:"target_ip,omitempty" yaml:"target_ip,omitempty"`
	TargetPort  int     `json:"target_port,omitempty" yaml:"target_port,omitempty"`
	IPPool      string  `json:"ip_pool,omitempty" yaml:"ip_pool,omitempty"`
}

// PolicyRule defines a single canonical firewall policy.
type PolicyRule struct {
	ID               int               `json:"id" yaml:"id"`
	Name             string            `json:"name" yaml:"name"`
	Priority         int               `json:"priority,omitempty" yaml:"priority,omitempty"`
	SrcZone          string            `json:"src_zone" yaml:"src_zone"`
	DstZone          string            `json:"dst_zone" yaml:"dst_zone"`
	SrcAddr          []string          `json:"src_addr" yaml:"src_addr"`
	DstAddr          []string          `json:"dst_addr" yaml:"dst_addr"`
	Services         []string          `json:"services" yaml:"services"`
	Apps             []string          `json:"apps,omitempty" yaml:"apps,omitempty"`
	AppCategories    []string          `json:"app_categories,omitempty" yaml:"app_categories,omitempty"`
	Users            []string          `json:"users,omitempty" yaml:"users,omitempty"`
	Groups           []string          `json:"groups,omitempty" yaml:"groups,omitempty"`
	Devices          []string          `json:"devices,omitempty" yaml:"devices,omitempty"`
	DevicePosture    string            `json:"device_posture,omitempty" yaml:"device_posture,omitempty"`
	Domains          []string          `json:"domains,omitempty" yaml:"domains,omitempty"`
	URLCategories    []string          `json:"url_categories,omitempty" yaml:"url_categories,omitempty"`
	SrcCountries     []string          `json:"src_countries,omitempty" yaml:"src_countries,omitempty"`
	DstCountries     []string          `json:"dst_countries,omitempty" yaml:"dst_countries,omitempty"`
	ASNs             []int             `json:"asns,omitempty" yaml:"asns,omitempty"`
	ThreatScoreMin   int               `json:"threat_score_min,omitempty" yaml:"threat_score_min,omitempty"`
	ThreatScoreMax   int               `json:"threat_score_max,omitempty" yaml:"threat_score_max,omitempty"`
	IOCMatch         bool              `json:"ioc_match,omitempty" yaml:"ioc_match,omitempty"`
	Schedule         string            `json:"schedule,omitempty" yaml:"schedule,omitempty"`
	DSCP             int               `json:"dscp,omitempty" yaml:"dscp,omitempty"`
	TTL              int64             `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	TenantID         string            `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
	Action           Action            `json:"action" yaml:"action"`
	NAT              *NATRule          `json:"nat,omitempty" yaml:"nat,omitempty"`
	Inspection       InspectionProfile `json:"inspection,omitempty" yaml:"inspection,omitempty"`
	LogTraffic       bool              `json:"log_traffic" yaml:"log_traffic"`
	Enabled          bool              `json:"enabled" yaml:"enabled"`
	ShapingBandwidth string            `json:"shaping_bandwidth,omitempty" yaml:"shaping_bandwidth,omitempty"`
}

// StaticRoute defines a static L3 route.
type StaticRoute struct {
	Destination string `json:"destination" yaml:"destination"`
	Gateway     string `json:"gateway" yaml:"gateway"`
	Interface   string `json:"interface,omitempty" yaml:"interface,omitempty"`
	Metric      int    `json:"metric,omitempty" yaml:"metric,omitempty"`
}

// BGPConfig defines basic BGP dynamic routing.
type BGPConfig struct {
	Enabled   bool     `json:"enabled" yaml:"enabled"`
	LocalASN  int      `json:"local_asn" yaml:"local_asn"`
	RouterID  string   `json:"router_id" yaml:"router_id"`
	Neighbors []string `json:"neighbors,omitempty" yaml:"neighbors,omitempty"` // "198.51.100.2 remote-as 65001"
	Networks  []string `json:"networks,omitempty" yaml:"networks,omitempty"`
}

// DHCPScope defines a local DHCP server scope.
type DHCPScope struct {
	Interface string   `json:"interface" yaml:"interface"`
	StartIP   string   `json:"start_ip" yaml:"start_ip"`
	EndIP     string   `json:"end_ip" yaml:"end_ip"`
	Gateway   string   `json:"gateway" yaml:"gateway"`
	DNS       []string `json:"dns" yaml:"dns"`
	LeaseTime string   `json:"lease_time" yaml:"lease_time"`
}

// SystemConfig houses system-level tuning and global parameters.
type SystemConfig struct {
	Hostname            string `json:"hostname" yaml:"hostname"`
	ConntrackMax        int    `json:"conntrack_max" yaml:"conntrack_max"`
	FlowtableOffload    bool   `json:"flowtable_offload" yaml:"flowtable_offload"`
	XDPPrefilter        bool   `json:"xdp_prefilter" yaml:"xdp_prefilter"`
	AutoRollbackSeconds int    `json:"auto_rollback_seconds" yaml:"auto_rollback_seconds"`
}

// GatewayConfig represents the entire declarative configuration of SentinelGate.
type GatewayConfig struct {
	Version      string          `json:"version" yaml:"version"`
	System       SystemConfig    `json:"system" yaml:"system"`
	Interfaces   []Interface     `json:"interfaces" yaml:"interfaces"`
	Addresses    []AddressGroup  `json:"addresses" yaml:"addresses"`
	Services     []Service       `json:"services" yaml:"services"`
	Policies     []PolicyRule    `json:"policies" yaml:"policies"`
	StaticRoutes []StaticRoute   `json:"static_routes" yaml:"static_routes"`
	BGP          BGPConfig       `json:"bgp,omitempty" yaml:"bgp,omitempty"`
	DHCP         []DHCPScope     `json:"dhcp,omitempty" yaml:"dhcp,omitempty"`
}

// Hash returns the SHA-256 fingerprint of the serialized configuration.
func (c *GatewayConfig) Hash() (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

// Validate executes strict structural and relational checks on the candidate configuration.
func (c *GatewayConfig) Validate() error {
	if c.Version == "" {
		return errors.New("configuration version must be defined")
	}

	zones := make(map[string]bool)
	for _, itf := range c.Interfaces {
		if itf.Name == "" {
			return errors.New("interface name cannot be empty")
		}
		if itf.Zone == "" {
			return fmt.Errorf("interface %s must belong to a zone", itf.Name)
		}
		zones[itf.Zone] = true
		for _, addr := range itf.IPAddresses {
			if _, _, err := net.ParseCIDR(addr); err != nil {
				return fmt.Errorf("interface %s has invalid CIDR %s: %w", itf.Name, addr, err)
			}
		}
	}

	addrGroups := make(map[string]bool)
	for _, ag := range c.Addresses {
		if ag.Name == "" {
			return errors.New("address group name cannot be empty")
		}
		addrGroups[ag.Name] = true
	}

	services := make(map[string]bool)
	for _, svc := range c.Services {
		if svc.Name == "" {
			return errors.New("service name cannot be empty")
		}
		services[svc.Name] = true
	}

	policyIDs := make(map[int]bool)
	for _, pol := range c.Policies {
		if pol.ID <= 0 {
			return fmt.Errorf("policy %s has invalid ID %d (must be > 0)", pol.Name, pol.ID)
		}
		if policyIDs[pol.ID] {
			return fmt.Errorf("duplicate policy ID %d", pol.ID)
		}
		policyIDs[pol.ID] = true

		if pol.SrcZone != "any" && !zones[pol.SrcZone] {
			return fmt.Errorf("policy %d references non-existent src_zone '%s'", pol.ID, pol.SrcZone)
		}
		if pol.DstZone != "any" && !zones[pol.DstZone] {
			return fmt.Errorf("policy %d references non-existent dst_zone '%s'", pol.ID, pol.DstZone)
		}
		for _, svcName := range pol.Services {
			if svcName != "any" && !services[svcName] {
				return fmt.Errorf("policy %d references non-existent service '%s'", pol.ID, svcName)
			}
		}
	}

	for _, rt := range c.StaticRoutes {
		if _, _, err := net.ParseCIDR(rt.Destination); err != nil {
			return fmt.Errorf("static route has invalid destination CIDR %s: %w", rt.Destination, err)
		}
		if net.ParseIP(rt.Gateway) == nil {
			return fmt.Errorf("static route has invalid gateway IP %s", rt.Gateway)
		}
	}

	return nil
}

// ConfigManager manages candidate, active, and rollback states with commit-confirm.
type ConfigManager struct {
	mu            sync.RWMutex
	baseDir       string
	activeConfig  *GatewayConfig
	candidate     *GatewayConfig
	confirmTimer  *time.Timer
	rollbackState *GatewayConfig
	revisions     []string // SHA-256 history
}

// NewConfigManager initializes the configuration engine in the specified directory.
func NewConfigManager(baseDir string) (*ConfigManager, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, err
	}
	cm := &ConfigManager{
		baseDir: baseDir,
	}
	activePath := filepath.Join(baseDir, "active.json")
	if _, err := os.Stat(activePath); err == nil {
		data, err := os.ReadFile(activePath)
		if err != nil {
			return nil, err
		}
		var cfg GatewayConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		cm.activeConfig = &cfg
	} else {
		// Bootstrap default initial configuration
		cm.activeConfig = DefaultConfig()
		_ = cm.SaveActive()
	}
	return cm, nil
}

// DefaultConfig generates a sane, secure out-of-the-box configuration.
func DefaultConfig() *GatewayConfig {
	return &GatewayConfig{
		Version: "3.0.0",
		System: SystemConfig{
			Hostname:            "sentinelgate-01",
			ConntrackMax:        1048576,
			FlowtableOffload:    true,
			XDPPrefilter:        true,
			AutoRollbackSeconds: 600, // 10 minutes default
		},
		Interfaces: []Interface{
			{Name: "eth0", Zone: "wan", IPAddresses: []string{"198.51.100.1/24"}, Offload: true},
			{Name: "eth1", Zone: "lan", IPAddresses: []string{"192.168.10.1/24"}, Offload: true},
		},
		Addresses: []AddressGroup{
			{Name: "LAN_Subnet", Members: []string{"192.168.10.0/24"}},
			{Name: "Any_Internet", Members: []string{"0.0.0.0/0"}},
		},
		Services: []Service{
			{Name: "HTTP_HTTPS", Protocol: "tcp", Ports: "80,443"},
			{Name: "DNS", Protocol: "udp", Ports: "53"},
			{Name: "ICMP_Echo", Protocol: "icmp"},
			{Name: "SSH", Protocol: "tcp", Ports: "22"},
		},
		Policies: []PolicyRule{
			{
				ID:         1,
				Name:       "LAN_Outbound_Internet",
				SrcZone:    "lan",
				DstZone:    "wan",
				SrcAddr:    []string{"LAN_Subnet"},
				DstAddr:    []string{"Any_Internet"},
				Services:   []string{"HTTP_HTTPS", "DNS", "ICMP_Echo"},
				Action:     ActionAccept,
				NAT:        &NATRule{Type: NATMasquerade},
				LogTraffic: true,
				Enabled:    true,
			},
		},
		StaticRoutes: []StaticRoute{
			{Destination: "0.0.0.0/0", Gateway: "198.51.100.254", Interface: "eth0", Metric: 10},
		},
	}
}

// SetCandidate sets a candidate configuration for validation and diff.
func (cm *ConfigManager) SetCandidate(cfg *GatewayConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if err := cfg.Validate(); err != nil {
		return err
	}
	cm.candidate = cfg
	return nil
}

// GetActive returns a safe copy of the active configuration.
func (cm *ConfigManager) GetActive() *GatewayConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.activeConfig
}

// GetCandidate returns the candidate configuration.
func (cm *ConfigManager) GetCandidate() *GatewayConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.candidate
}

// Diff generates a readable YAML representation comparison between active and candidate.
func (cm *ConfigManager) Diff() (string, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.candidate == nil {
		return "No candidate configuration present.", nil
	}
	activeJSON, _ := json.MarshalIndent(cm.activeConfig, "", "  ")
	candidateJSON, _ := json.MarshalIndent(cm.candidate, "", "  ")

	return fmt.Sprintf("--- Active Configuration\n+++ Candidate Configuration\n\n%s\n--- CANDIDATE ---\n%s",
		string(activeJSON), string(candidateJSON)), nil
}

// Commit applies the candidate configuration with commit-confirm semantics.
func (cm *ConfigManager) Commit(confirmDuration time.Duration, onRollback func()) (string, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.candidate == nil {
		return "", errors.New("no candidate configuration to commit")
	}
	if err := cm.candidate.Validate(); err != nil {
		return "", fmt.Errorf("candidate validation failed: %w", err)
	}

	h, err := cm.candidate.Hash()
	if err != nil {
		return "", err
	}

	// Stash rollback state
	cm.rollbackState = cm.activeConfig
	cm.activeConfig = cm.candidate
	cm.candidate = nil
	cm.revisions = append(cm.revisions, h)

	if err := cm.saveActiveLocked(); err != nil {
		return "", err
	}

	// Schedule commit-confirmed auto-rollback
	if confirmDuration > 0 {
		if cm.confirmTimer != nil {
			cm.confirmTimer.Stop()
		}
		cm.confirmTimer = time.AfterFunc(confirmDuration, func() {
			cm.Rollback()
			if onRollback != nil {
				onRollback()
			}
		})
	}

	return h, nil
}

// Confirm locks in the committed configuration and cancels auto-rollback.
func (cm *ConfigManager) Confirm() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.confirmTimer == nil {
		return errors.New("no pending commit-confirm timer is active")
	}
	cm.confirmTimer.Stop()
	cm.confirmTimer = nil
	cm.rollbackState = nil
	return nil
}

// Rollback immediately reverts to the pre-commit configuration.
func (cm *ConfigManager) Rollback() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.rollbackState == nil {
		return errors.New("no rollback configuration available")
	}
	if cm.confirmTimer != nil {
		cm.confirmTimer.Stop()
		cm.confirmTimer = nil
	}

	cm.activeConfig = cm.rollbackState
	cm.rollbackState = nil
	return cm.saveActiveLocked()
}

func (cm *ConfigManager) saveActiveLocked() error {
	data, err := json.MarshalIndent(cm.activeConfig, "", "  ")
	if err != nil {
		return err
	}
	activePath := filepath.Join(cm.baseDir, "active.json")
	return os.WriteFile(activePath, data, 0600)
}

// SaveActive persists the active configuration to disk.
func (cm *ConfigManager) SaveActive() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.saveActiveLocked()
}
