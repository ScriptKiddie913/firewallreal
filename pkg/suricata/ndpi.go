// Package suricata provides nDPI integration, TLS fingerprinting, and QUIC management.
package suricata

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// AppCategory classifies recognized applications into operational risk groups.
type AppCategory string

const (
	CategoryWeb        AppCategory = "Web"
	CategoryMedia      AppCategory = "StreamingMedia"
	CategoryP2P        AppCategory = "PeerToPeer"
	CategoryEncrypted  AppCategory = "EncryptedTunnel"
	CategoryManagement AppCategory = "RemoteManagement"
	CategoryMalicious  AppCategory = "MaliciousC2"
)

// ApplicationIdentity represents a recognized L7 protocol/application.
type ApplicationIdentity struct {
	Name        string      `json:"name"`
	Category    AppCategory `json:"category"`
	RiskScore   int         `json:"risk_score"` // 1 (low) to 5 (critical)
	JA3Hash     string      `json:"ja3_hash,omitempty"`
	JA4Fingerprint string   `json:"ja4_fingerprint,omitempty"`
	SNI         string      `json:"sni,omitempty"`
}

// AppClassifier performs L7 protocol matching and TLS client fingerprinting.
type AppClassifier struct {
	knownSignatures map[string]ApplicationIdentity
}

// NewAppClassifier creates a new protocol classifier.
func NewAppClassifier() *AppClassifier {
	c := &AppClassifier{
		knownSignatures: make(map[string]ApplicationIdentity),
	}
	c.bootstrapSignatures()
	return c
}

func (c *AppClassifier) bootstrapSignatures() {
	c.knownSignatures["youtube"] = ApplicationIdentity{
		Name: "YouTube", Category: CategoryMedia, RiskScore: 1,
	}
	c.knownSignatures["bittorrent"] = ApplicationIdentity{
		Name: "BitTorrent", Category: CategoryP2P, RiskScore: 4,
	}
	c.knownSignatures["wireguard"] = ApplicationIdentity{
		Name: "WireGuard", Category: CategoryEncrypted, RiskScore: 2,
	}
	c.knownSignatures["cobaltstrike"] = ApplicationIdentity{
		Name: "CobaltStrike_Beacon", Category: CategoryMalicious, RiskScore: 5,
	}
}

// ComputeJA3 generates a JA3 fingerprint hash from TLS Client Hello parameters.
func ComputeJA3(version uint16, cipherSuites []uint16, extensions []uint16, curves []uint16, pointFormats []uint8) string {
	var ciphersStr, extsStr, curvesStr, formatsStr []string

	for _, c := range cipherSuites {
		ciphersStr = append(ciphersStr, fmt.Sprintf("%d", c))
	}
	for _, e := range extensions {
		extsStr = append(extsStr, fmt.Sprintf("%d", e))
	}
	for _, cv := range curves {
		curvesStr = append(curvesStr, fmt.Sprintf("%d", cv))
	}
	for _, pf := range pointFormats {
		formatsStr = append(formatsStr, fmt.Sprintf("%d", pf))
	}

	rawString := fmt.Sprintf("%d,%s,%s,%s,%s",
		version,
		strings.Join(ciphersStr, "-"),
		strings.Join(extsStr, "-"),
		strings.Join(curvesStr, "-"),
		strings.Join(formatsStr, "-"))

	h := md5.Sum([]byte(rawString))
	return hex.EncodeToString(h[:])
}

// HandleQUIC inspects a QUIC / HTTP3 flow and decides if it should be downgraded or permitted.
func (c *AppClassifier) HandleQUIC(blockQUIC bool) (action string, reason string) {
	if blockQUIC {
		// Dropping UDP 443 causes modern web browsers (Chrome, Firefox, Safari)
		// to automatically fallback to TCP TLS 1.3, enabling full proxy inspection.
		return "drop", "QUIC downgraded to TCP TLS 1.3 for deep packet inspection"
	}
	return "accept", "QUIC permitted"
}
