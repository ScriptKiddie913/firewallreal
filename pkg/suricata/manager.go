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

	// Ensure the real Suricata control socket exists; no fake/mock reload
	if _, err := os.Stat(m.socketPath); err != nil {
		return fmt.Errorf("suricata command socket not found at %s: daemon not running or socket misconfigured (%w)", m.socketPath, err)
	}

	conn, err := net.Dial("unix", m.socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to Suricata command socket at %s: %w", m.socketPath, err)
	}
	defer conn.Close()

	// Set deadline to avoid hanging indefinitely
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Suricata Unix socket protocol command: {"command": "reload-rules"}
	cmd := map[string]string{"command": "reload-rules"}
	payload, _ := json.Marshal(cmd)
	if _, err := conn.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("failed to send reload command to Suricata: %w", err)
	}

	// Read and verify Suricata response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed reading reload acknowledgment from Suricata: %w", err)
	}

	var resp struct {
		Return string `json:"return"`
		Error  string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(buf[:n], &resp); err == nil {
		if resp.Return != "OK" {
			return fmt.Errorf("suricata rule reload failed: %s", resp.Error)
		}
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
