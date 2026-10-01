// Package tlsproxy implements the privacy-conscious TLS 1.2/1.3 forward inspection proxy,
// internal CA leaf certificate minting, and strict category bypass engine.
package tlsproxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
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
	mu                  sync.RWMutex
	caCert              *x509.Certificate
	caPrivKey           *ecdsa.PrivateKey
	leafCache           map[string]*tlsCertEntry
	bypassEngine        map[string]bool
	pinningFailures     map[string]int
	autoBypassThreshold int
}

type tlsCertEntry struct {
	certPEM []byte
	keyPEM  []byte
}

// NewTLSInspectionEngine initializes the forward proxy with a self-generated or imported Root CA using ECDSA P-256.
func NewTLSInspectionEngine() (*TLSInspectionEngine, error) {
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		caCert:              caCert,
		caPrivKey:           caPriv,
		leafCache:           make(map[string]*tlsCertEntry),
		bypassEngine:        make(map[string]bool),
		pinningFailures:     make(map[string]int),
		autoBypassThreshold: 3,
	}

	for _, domain := range DefaultPrivacyBypassList {
		engine.bypassEngine[domain] = true
	}

	return engine, nil
}

// ShouldBypass verifies if the target SNI matches privacy exemptions (banking, healthcare, gov).

// RecordPinningFailure tracks downstream client pinning rejections and triggers auto-bypass if threshold is reached.
func (e *TLSInspectionEngine) RecordPinningFailure(sni string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	sni = strings.ToLower(strings.TrimSpace(sni))
	if sni == "" {
		return false
	}
	e.pinningFailures[sni]++
	if e.pinningFailures[sni] >= e.autoBypassThreshold {
		e.bypassEngine[sni] = true
		return true
	}
	return false
}

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

// MintLeafCertificate dynamically creates a valid TLS leaf certificate for the inspected domain using ECDSA P-256.
func (e *TLSInspectionEngine) MintLeafCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Fast path: read lock check for cached certificate
	e.mu.RLock()
	if entry, ok := e.leafCache[domain]; ok {
		e.mu.RUnlock()
		return entry.certPEM, entry.keyPEM, nil
	}
	e.mu.RUnlock()

	// Cache miss: generate ultra-fast ECDSA P-256 leaf key (microseconds vs 20ms+ RSA-2048)
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		KeyUsage:     x509.KeyUsageDigitalSignature,
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

	keyBytes, err := x509.MarshalECPrivateKey(leafPriv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// Thread-safe update of the cache
	e.mu.Lock()
	e.leafCache[domain] = &tlsCertEntry{certPEM: certPEM, keyPEM: keyPEM}
	e.mu.Unlock()

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

// TLSProxy executes the forward proxy accept loop and stream inspection.
type TLSProxy struct {
	cfg           *ProxyConfig
	engine        *TLSInspectionEngine
	dlp           *DLPEngine
	fileInspector *FileInspector
	activeConns   sync.WaitGroup
	quit          chan struct{}
}

// NewTLSProxy initializes a full proxy with inspection engines.
func NewTLSProxy(cfg *ProxyConfig) (*TLSProxy, error) {
	if cfg == nil {
		cfg = &ProxyConfig{
			Mode:               ModeFullInspection,
			MinTLSVersion:      tls.VersionTLS12,
			StrictUpstreamCert: true,
			BypassList:         DefaultPrivacyBypassList,
		}
	}
	engine, err := NewTLSInspectionEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to init TLS inspection engine: %w", err)
	}
	for _, domain := range cfg.BypassList {
		engine.bypassEngine[domain] = true
	}

	return &TLSProxy{
		cfg:           cfg,
		engine:        engine,
		dlp:           NewDLPEngine(),
		fileInspector: NewFileInspector(),
		quit:          make(chan struct{}),
	}, nil
}

// Serve begins accepting transparent or forwarded TLS connections.
func (p *TLSProxy) Serve(ln net.Listener) error {
	defer ln.Close()
	log.Printf("[INFO] SentinelGate TLS Inspection Proxy listening on %s (Mode: %s)", ln.Addr(), p.cfg.Mode)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.quit:
				return nil
			default:
				log.Printf("[WARN] Accept error: %v", err)
				continue
			}
		}

		p.activeConns.Add(1)
		go func(c net.Conn) {
			defer p.activeConns.Done()
			p.handleConn(c)
		}(conn)
	}
}

// Close gracefully stops the proxy.
func (p *TLSProxy) Close() error {
	close(p.quit)
	p.activeConns.Wait()
	return nil
}

// peekSNI reads the ClientHello record to extract SNI without consuming data from the downstream connection.
func peekSNI(r io.Reader) (string, io.Reader, error) {
	header := make([]byte, 5)
	n, err := io.ReadFull(r, header)
	if err != nil {
		return "", bytes.NewReader(header[:n]), err
	}

	// Quick check for TLS Handshake record (0x16)
	if header[0] != 0x16 {
		return "", io.MultiReader(bytes.NewReader(header), r), nil
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen <= 0 || recordLen > 16384 {
		return "", io.MultiReader(bytes.NewReader(header), r), nil
	}

	body := make([]byte, recordLen)
	if _, err := io.ReadFull(r, body); err != nil {
		combined := io.MultiReader(bytes.NewReader(header), bytes.NewReader(body), r)
		return "", combined, err
	}

	data := append(header, body...)
	combinedReader := io.MultiReader(bytes.NewReader(data), r)

	if len(data) < 43 || data[5] != 0x01 {
		return "", combinedReader, nil
	}

	// Minimal ClientHello parser to extract SNI extension
	sni := ""
	pos := 43 // Skip record header + version + random
	if pos < len(data) {
		sessionIDLen := int(data[pos])
		pos += 1 + sessionIDLen
	}
	if pos+2 <= len(data) {
		cipherSuiteLen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2 + cipherSuiteLen
	}
	if pos+1 <= len(data) {
		compressionLen := int(data[pos])
		pos += 1 + compressionLen
	}
	if pos+2 <= len(data) {
		extTotalLen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2
		end := pos + extTotalLen
		if end > len(data) {
			end = len(data)
		}
		for pos+4 <= end {
			extType := int(data[pos])<<8 | int(data[pos+1])
			extLen := int(data[pos+2])<<8 | int(data[pos+3])
			pos += 4
			if extType == 0 && pos+extLen <= end { // Server Name Indication
				sniPos := pos + 2 // skip server name list length
				if sniPos+3 <= end {
					nameLen := int(data[sniPos+1])<<8 | int(data[sniPos+2])
					if sniPos+3+nameLen <= end {
						sni = string(data[sniPos+3 : sniPos+3+nameLen])
					}
				}
				break
			}
			pos += extLen
		}
	}

	return sni, combinedReader, nil
}

func (p *TLSProxy) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	sni, stream, err := peekSNI(clientConn)
	if err != nil {
		return
	}
	if sni == "" {
		sni = "default.local"
	}

	targetAddr := net.JoinHostPort(sni, "443")

	// Check if this domain is on the privacy bypass list
	if p.cfg.Mode == ModeBypass || p.engine.ShouldBypass(sni) {
		p.spliceDirect(clientConn, stream, targetAddr)
		return
	}

	// Dynamic certificate minting for inspection
	certPEM, keyPEM, err := p.engine.MintLeafCertificate(sni)
	if err != nil {
		log.Printf("[ERROR] Leaf mint error for %s: %v", sni, err)
		return
	}

	leafTLSCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Printf("[ERROR] Keypair parse error: %v", err)
		return
	}

	// Dial upstream with strict verification
	upstreamTLS, err := tls.Dial("tcp", targetAddr, &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Printf("[WARN] Upstream TLS dial failed for %s: %v", targetAddr, err)
		return
	}
	defer upstreamTLS.Close()

	if p.cfg.StrictUpstreamCert {
		certs := upstreamTLS.ConnectionState().PeerCertificates
		if err := p.engine.ValidateUpstreamCertificate(certs, sni); err != nil {
			log.Printf("[SECURITY] Upstream cert rejected for %s: %v", sni, err)
			return
		}
	}

	// Client TLS handshake with minted leaf
	tlsDownstream := tls.Server(&bufferedConn{Conn: clientConn, r: stream}, &tls.Config{
		Certificates: []tls.Certificate{leafTLSCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsDownstream.Handshake(); err != nil {
		return
	}
	defer tlsDownstream.Close()

	// Bidirectional stream copy with inspection tap
	var wg sync.WaitGroup
	wg.Add(2)

	// Downstream -> Upstream (Inspection for DLP)
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, rerr := tlsDownstream.Read(buf)
			if n > 0 {
				payload := string(buf[:n])
				violations := p.dlp.ScanStream(payload)
				if len(violations) > 0 {
					log.Printf("[DLP VIOLATION] Domain %s leaked: %s", sni, violations[0].Type)
				}
				if _, werr := upstreamTLS.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
	}()

	// Upstream -> Downstream (Inspection for Malicious Binaries / AV)
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, rerr := upstreamTLS.Read(buf)
			if n > 0 {
				verdict := p.fileInspector.InspectBuffer(sni+"_stream", buf[:n])
				if verdict.Verdict == VerdictMalicious {
					log.Printf("[AV DETECTED] Threat %s blocked in stream %s", verdict.ThreatName, sni)
					break
				}
				if _, werr := tlsDownstream.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
	}()

	wg.Wait()
}

func (p *TLSProxy) spliceDirect(downstream net.Conn, downstreamReader io.Reader, targetAddr string) {
	upstream, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	go func() {
		io.Copy(upstream, downstreamReader)
	}()
	io.Copy(downstream, upstream)
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

