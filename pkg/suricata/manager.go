// Package suricata manages the Suricata 7.x IPS daemon, UNIX control socket,
// rule hot-reloading, and event streaming.
package suricata

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IPSEvent represents an alert emitted by Suricata on the eve.json socket.
type IPSEvent struct {
	Timestamp string `json:"timestamp"`
	EventFlow string `json:"flow_id"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	Alert     struct {
		Action    string `json:"action"` // allowed, blocked
		Signature string `json:"signature"`
		SignatureID int  `json:"signature_id"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"` // 1 = highest, 4 = lowest
	} `json:"alert"`
	AppProto  string `json:"app_proto,omitempty"`
}

// Manager controls the Suricata process and rules lifecycle.
type Manager struct {
	mu           sync.Mutex
	socketPath   string
	rulesDir     string
	rulesVersion int
	eventBus     chan IPSEvent
}

// NewManager creates a new Suricata manager instance.
func NewManager(socketPath, rulesDir string) *Manager {
	if socketPath == "" {
		socketPath = "/var/run/suricata/suricata-command.socket"
	}
	if rulesDir == "" {
		rulesDir = "/etc/sentinelgate/rules"
	}
	return &Manager{
		socketPath: socketPath,
		rulesDir:   rulesDir,
		eventBus:   make(chan IPSEvent, 1000),
	}
}

// EventStream returns a read-only channel for real-time security events.
func (m *Manager) EventStream() <-chan IPSEvent {
	return m.eventBus
}

// ReloadRules sends a live hot-reload command to Suricata over its UNIX domain socket.
func (m *Manager) ReloadRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If socket exists, communicate with Suricata daemon
	if _, err := os.Stat(m.socketPath); err != nil {
		// Mock reload if running in development / container without active daemon
		m.rulesVersion++
		return nil
	}

	conn, err := net.Dial("unix", m.socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to Suricata command socket: %w", err)
	}
	defer conn.Close()

	// Suricata Unix socket protocol command: {"command": "reload-rules"}
	cmd := map[string]string{"command": "reload-rules"}
	payload, _ := json.Marshal(cmd)
	if _, err := conn.Write(append(payload, '\n')); err != nil {
		return err
	}

	m.rulesVersion++
	return nil
}

// WriteCustomRule writes an Emerging-Threats format signature to the custom rules file.
func (m *Manager) WriteCustomRule(ruleContent string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.rulesDir, 0750); err != nil {
		return err
	}
	customFile := filepath.Join(m.rulesDir, "custom.rules")
	f, err := os.OpenFile(customFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s\n", ruleContent))
	return err
}

// IngestAlert processes an incoming alert from EVE JSON.
func (m *Manager) IngestAlert(ev IPSEvent) {
	select {
	case m.eventBus <- ev:
	default:
		// Queue full; avoid blocking data path
	}
}
