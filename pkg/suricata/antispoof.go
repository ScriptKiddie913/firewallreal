// Package suricata implements anti-spoofing validation to prevent attacker-forged
// packets from causing denial-of-service bans on legitimate hosts.
package suricata

import (
	"net"
	"sync"
	"time"
)

// HostReputation tracks connection authenticity and attack history.
type HostReputation struct {
	IP                 string
	EstablishedSessions int
	UncompletedSYNs    int
	AttackScore        int
	LastSeen           time.Time
	HandshakeConfirmed bool
}

// AntiSpoofEngine manages threat attribution and anti-spoofing protection.
type AntiSpoofEngine struct {
	mu           sync.RWMutex
	hosts        map[string]*HostReputation
	protectedIPs map[string]bool
}

// NewAntiSpoofEngine creates an anti-spoof scoring manager.
func NewAntiSpoofEngine() *AntiSpoofEngine {
	e := &AntiSpoofEngine{
		hosts:        make(map[string]*HostReputation),
		protectedIPs: make(map[string]bool),
	}
	e.bootstrapProtectedIPs()
	return e
}

func (e *AntiSpoofEngine) bootstrapProtectedIPs() {
	// Whitelist localhost and common RFC1918 / Cloud DNS
	e.protectedIPs["127.0.0.1"] = true
	e.protectedIPs["1.1.1.1"] = true
	e.protectedIPs["8.8.8.8"] = true
}

// IsProtected checks if the IP can never be auto-banned.
func (e *AntiSpoofEngine) IsProtected(ipStr string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.protectedIPs[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return true
	}
	return false
}

// RecordHandshake marks that a full TCP 3-way handshake was observed from this IP.
func (e *AntiSpoofEngine) RecordHandshake(ipStr string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	h, ok := e.hosts[ipStr]
	if !ok {
		h = &HostReputation{IP: ipStr, LastSeen: time.Now()}
		e.hosts[ipStr] = h
	}
	h.EstablishedSessions++
	h.HandshakeConfirmed = true
	h.LastSeen = time.Now()
}

// EvaluateBanDecision computes whether an attack should result in a hard kernel ban.
func (e *AntiSpoofEngine) EvaluateBanDecision(ipStr string, attackSeverity int) (shouldBan bool, reason string) {
	if e.IsProtected(ipStr) {
		return false, "IP is protected / whitelisted (prevents lockout and spoof-DoS)"
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	h, ok := e.hosts[ipStr]
	if !ok {
		h = &HostReputation{IP: ipStr, LastSeen: time.Now()}
		e.hosts[ipStr] = h
	}

	h.AttackScore += attackSeverity
	h.LastSeen = time.Now()

	// Anti-spoofing rail: If TCP handshake was never confirmed,
	// do NOT ban the IP globally (drop individual packets instead).
	if !h.HandshakeConfirmed && h.AttackScore < 100 {
		return false, "Packet dropped, but global IP ban deferred pending TCP 3-way handshake verification"
	}

	if h.AttackScore >= 50 {
		return true, "Verified attacker source exceeded threat score threshold"
	}

	return false, "Score accumulating below threshold"
}
