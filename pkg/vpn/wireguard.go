// Package vpn orchestrates WireGuard remote access and strongSwan IPsec tunnels for SentinelGate.
package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// WireGuardPeer represents a connected client or branch endpoint.
type WireGuardPeer struct {
	Username    string    `json:"username"`
	PublicKey   string    `json:"public_key"`
	AllowedIPs  []string  `json:"allowed_ips"`
	AssignedIP  string    `json:"assigned_ip"`
	Endpoint    string    `json:"endpoint,omitempty"`
	LastSeen    time.Time `json:"last_seen"`
	RxBytes     uint64    `json:"rx_bytes"`
	TxBytes     uint64    `json:"tx_bytes"`
	Active      bool      `json:"active"`
}

// WireGuardServer manages the WireGuard kernel interface and client IPAM.
type WireGuardServer struct {
	mu         sync.RWMutex
	interfaceName string
	listenPort int
	serverPriv string
	serverPub  string
	subnetCIDR string
	nextIP     net.IP
	peers      map[string]*WireGuardPeer // publicKey -> peer
}

// NewWireGuardServer initializes the remote access VPN server.
func NewWireGuardServer(iface string, port int, subnet string) (*WireGuardServer, error) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	ip, _, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}
	next := make(net.IP, len(ip))
	copy(next, ip)
	next[len(next)-1] = 2 // Start assigning from .2 (server is .1)

	return &WireGuardServer{
		interfaceName: iface,
		listenPort: port,
		serverPriv: priv,
		serverPub:  pub,
		subnetCIDR: subnet,
		nextIP:     next,
		peers:      make(map[string]*WireGuardPeer),
	}, nil
}

// GenerateKeyPair generates a Curve25519 private/public keypair.
func GenerateKeyPair() (privateKeyBase64 string, publicKeyBase64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	// Clamp private key according to Curve25519 specification
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub[:]),
		nil
}

// RegisterClientPeer generates a client config and provisions the peer.
func (s *WireGuardServer) RegisterClientPeer(username string, fullTunnel bool, dnsServers []string) (clientConfig string, peer *WireGuardPeer, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cPriv, cPub, err := GenerateKeyPair()
	if err != nil {
		return "", nil, err
	}

	clientIP := s.nextIP.String()
	s.nextIP[len(s.nextIP)-1]++

	allowed := "0.0.0.0/0, ::/0"
	if !fullTunnel {
		allowed = s.subnetCIDR
	}

	dns := "1.1.1.1, 8.8.8.8"
	if len(dnsServers) > 0 {
		dns = fmt.Sprintf("%v", dnsServers)
	}

	peer = &WireGuardPeer{
		Username:   username,
		PublicKey:  cPub,
		AllowedIPs: []string{fmt.Sprintf("%s/32", clientIP)},
		AssignedIP: clientIP,
		LastSeen:   time.Now(),
		Active:     true,
	}
	s.peers[cPub] = peer

	clientConfig = fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
DNS = %s

[Peer]
PublicKey = %s
Endpoint = vpn.company.com:%d
AllowedIPs = %s
PersistentKeepalive = 25
`, cPriv, clientIP, dns, s.serverPub, s.listenPort, allowed)

	return clientConfig, peer, nil
}
