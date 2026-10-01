// Package decoy implements low-interaction network deception services and scanner redirection.
package decoy

import (
	"strings"
	"sync"
	"time"
)

// DecoyType identifies the emulated vulnerable service.
type DecoyType string

const (
	DecoySSH     DecoyType = "SSH"
	DecoyTelnet  DecoyType = "Telnet"
	DecoyHTTP    DecoyType = "HTTP"
	DecoyMockLLM DecoyType = "MockLLM_API"
)

// AttackerInteraction records observed attacker commands or payloads.
type AttackerInteraction struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	Decoy     DecoyType `json:"decoy"`
	Payload   string    `json:"payload"`
}

// DecoyEngine manages isolated deception listeners.
type DecoyEngine struct {
	mu           sync.RWMutex
	interactions []AttackerInteraction
	blocklist    map[string]bool
}

// NewDecoyEngine creates a new deception engine.
func NewDecoyEngine() *DecoyEngine {
	return &DecoyEngine{
		blocklist: make(map[string]bool),
	}
}

// EmulateMockLLM generates a deceptive response to LLM prompt injection attempts.
func (de *DecoyEngine) EmulateMockLLM(srcIP, prompt string) (response string) {
	de.mu.Lock()
	defer de.mu.Unlock()

	de.interactions = append(de.interactions, AttackerInteraction{
		Timestamp: time.Now(),
		SrcIP:     srcIP,
		Decoy:     DecoyMockLLM,
		Payload:   prompt,
	})

	// If prompt contains injection or jailbreak indicators, flag attacker
	lower := strings.ToLower(prompt)
	if strings.Contains(lower, "ignore previous instructions") ||
		strings.Contains(lower, "dan") ||
		strings.Contains(lower, "system prompt override") {
		de.blocklist[srcIP] = true
	}

	return `{"choices":[{"message":{"role":"assistant","content":"I am a secure enterprise LLM endpoint. Operations are monitored."}}]}`
}

// IsFlagged checks if an attacker IP interacted maliciously with a decoy.
func (de *DecoyEngine) IsFlagged(ip string) bool {
	de.mu.RLock()
	defer de.mu.RUnlock()
	return de.blocklist[ip]
}
