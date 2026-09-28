// Package ha provides centralized fleet management and drift detection for SentinelGate clusters.
package ha

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ApplianceNode represents a managed physical or virtual gateway in the fleet.
type ApplianceNode struct {
	ID             string    `json:"id"`
	Hostname       string    `json:"hostname"`
	ManagementIP   string    `json:"management_ip"`
	ClusterRole    NodeRole  `json:"cluster_role"`
	ActiveConfigHash string  `json:"active_config_hash"`
	TemplateID     string    `json:"template_id"`
	DriftDetected  bool      `json:"drift_detected"`
	LastSeen       time.Time `json:"last_seen"`
	Version        string    `json:"version"`
}

// FleetController tracks multi-site gateway appliances and policy templates.
type FleetController struct {
	mu        sync.RWMutex
	nodes     map[string]*ApplianceNode
	templates map[string]string // templateID -> expected config SHA256
}

// NewFleetController creates a new central fleet orchestrator.
func NewFleetController() *FleetController {
	return &FleetController{
		nodes:     make(map[string]*ApplianceNode),
		templates: make(map[string]string),
	}
}

// RegisterTemplate registers an authoritative policy template.
func (fc *FleetController) RegisterTemplate(templateID string, configBytes []byte) string {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	h := sha256.Sum256(configBytes)
	hashStr := hex.EncodeToString(h[:])
	fc.templates[templateID] = hashStr
	return hashStr
}

// HeartbeatNode processes a periodic node check-in and checks for policy drift.
func (fc *FleetController) HeartbeatNode(nodeID, hostname, ip, templateID, configHash, version string, role NodeRole) *ApplianceNode {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	drift := false
	if expected, ok := fc.templates[templateID]; ok {
		if expected != configHash {
			drift = true
		}
	}

	node := &ApplianceNode{
		ID:               nodeID,
		Hostname:         hostname,
		ManagementIP:     ip,
		ClusterRole:      role,
		ActiveConfigHash: configHash,
		TemplateID:       templateID,
		DriftDetected:    drift,
		LastSeen:         time.Now(),
		Version:          version,
	}

	fc.nodes[nodeID] = node
	return node
}
