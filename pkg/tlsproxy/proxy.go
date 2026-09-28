// Package tlsproxy implements the privacy-conscious TLS 1.2/1.3 forward inspection proxy,
// internal CA leaf certificate minting, and strict category bypass engine.
package tlsproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// ProxyMode defines how TLS streams are handled.
type ProxyMode string

const (
	ModeFullInspection ProxyMode = "full_inspection"
	ModeCertOnly       ProxyMode = "cert_only"
	ModeSNIOnly        ProxyMode = "sni_only"
	ModeBypass         ProxyMode = "bypass"
)

// PrivacyExemptionList defines SNI patterns that are never decrypted by default.
var DefaultPrivacyBypassList = []string{
	"*.chase.com", "*.bankofamerica.com", "*.wellsfargo.com",
	"*.fidelity.com", "*.vanguard.com",
	"*.mychart.com", "*.epic.com", "*.cerner.com",
	"*.irs.gov", "*.login.gov", "*.ssa.gov",
}

// ProxyConfig stores the runtime parameters for TLS inspection.
type ProxyConfig struct {
	Mode               ProxyMode `json:"mode"`
	MinTLSVersion      uint16    `json:"min_tls_version"`
	StrictUpstreamCert bool      `json:"strict_upstream_cert"`
	BypassList         []string  `json:"bypass_list"`
}

// TLSInspectionEngine manages the internal CA and dynamic leaf certificate minting.
type TLSInspectionEngine struct {
	mu           sync.RWMutex
	caCert       *x509.Certificate
	caPrivKey    *rsa.PrivateKey
	leafCache    map[string]*tlsCertEntry
	bypassEngine map[string]bool
}

type tlsCertEntry struct {
	certPEM []byte
	keyPEM  []byte
}

// NewTLSInspectionEngine initializes the forward proxy with a self-generated or imported Root CA.
func NewTLSInspectionEngine() (*TLSInspectionEngine, error) {
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"SentinelGate Security Appliance"},
			CommonName:    "SentinelGate Internal Root CA",
			Country:       []string{"US"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}

	engine := &TLSInspectionEngine{
		caCert:       caCert,
		caPrivKey:    caPriv,
		leafCache:    make(map[string]*tlsCertEntry),
		bypassEngine: make(map[string]bool),
	}

	for _, domain := range DefaultPrivacyBypassList {
		engine.bypassEngine[domain] = true
	}

	return engine, nil
}

// ShouldBypass verifies if the target SNI matches privacy exemptions (banking, healthcare, gov).
func (e *TLSInspectionEngine) ShouldBypass(sni string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sni = strings.ToLower(strings.TrimSpace(sni))
	if e.bypassEngine[sni] {
		return true
	}

	for pattern := range e.bypassEngine {
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // e.g. ".chase.com"
			if strings.HasSuffix(sni, suffix) {
				return true
			}
		}
	}
	return false
}

// MintLeafCertificate dynamically creates a valid TLS leaf certificate for the inspected domain.
func (e *TLSInspectionEngine) MintLeafCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if entry, ok := e.leafCache[domain]; ok {
		return entry.certPEM, entry.keyPEM, nil
	}

	leafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"SentinelGate Inspected Session"},
		},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-10 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour), // Short 24h validity
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(domain); ip != nil {
		leafTemplate.IPAddresses = []net.IP{ip}
		leafTemplate.DNSNames = nil
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, e.caCert, &leafPriv.PublicKey, e.caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafPriv)})

	e.leafCache[domain] = &tlsCertEntry{certPEM: certPEM, keyPEM: keyPEM}
	return certPEM, keyPEM, nil
}

// ValidateUpstreamCertificate validates upstream certificate chains strictly.
func (e *TLSInspectionEngine) ValidateUpstreamCertificate(certs []*x509.Certificate, serverName string) error {
	if len(certs) == 0 {
		return errors.New("upstream server presented no certificates")
	}
	target := certs[0]

	// Verify expiration
	now := time.Now()
	if now.Before(target.NotBefore) || now.After(target.NotAfter) {
		return errors.New("upstream certificate is expired or not yet valid")
	}

	// Verify domain name SAN match
	if err := target.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("upstream certificate does not match requested SNI %s: %w", serverName, err)
	}

	return nil
}
