// Package main implements sfw-certgen, a pure Go stdlib utility for generating
// ECDSA P-256 self-signed certificates and managing system CA trust stores.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sfw-certgen <generate|install-ca> [options]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		genFlags := flag.NewFlagSet("generate", flag.ExitOnError)
		certPath := genFlags.String("cert", "console.crt", "Output certificate path")
		keyPath := genFlags.String("key", "console.key", "Output private key path")
		cn := genFlags.String("cn", "sentinelfw", "Common Name")
		days := genFlags.Int("days", 825, "Certificate validity in days")
		genFlags.Parse(os.Args[2:])

		if err := generateCert(*certPath, *keyPath, *cn, *days); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully generated certificate: %s and key: %s\n", *certPath, *keyPath)

	case "install-ca":
		caFlags := flag.NewFlagSet("install-ca", flag.ExitOnError)
		caFile := caFlags.String("ca", "", "Path to CA certificate PEM file")
		caFlags.Parse(os.Args[2:])

		if *caFile == "" {
			fmt.Fprintln(os.Stderr, "Error: -ca flag is required")
			os.Exit(1)
		}
		if err := installCA(*caFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error installing CA: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Successfully installed CA certificate into system trust store.")

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func generateCert(certPath, keyPath, cn string, days int) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"SentinelFW"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:              []string{cn, "localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	if d := filepath.Dir(certPath); d != "." && d != "" {
		_ = os.MkdirAll(d, 0755)
	}
	if d := filepath.Dir(keyPath); d != "." && d != "" {
		_ = os.MkdirAll(d, 0700)
	}

	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", certPath, err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate data: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", keyPath, err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("unable to marshal ECDSA private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write key data: %w", err)
	}

	return nil
}

func installCA(caPath string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("certutil", "-addstore", "Root", caPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("certutil error: %v, output: %s", err, string(out))
		}
		return nil
	}

	// Linux (Debian/Ubuntu/RHEL)
	targetDir := "/usr/local/share/ca-certificates"
	if _, err := os.Stat(targetDir); err == nil {
		dest := filepath.Join(targetDir, filepath.Base(caPath))
		data, err := os.ReadFile(caPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dest, data, 0644); err != nil {
			return err
		}
		cmd := exec.Command("update-ca-certificates")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("update-ca-certificates failed: %v (%s)", err, string(out))
		}
		return nil
	}

	return fmt.Errorf("unsupported OS or CA store location")
}
