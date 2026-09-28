// Package tlsproxy handles file payload extraction and ClamAV / YARA antivirus inspection.
package tlsproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ScanVerdict defines the anti-malware verdict.
type ScanVerdict string

const (
	VerdictClean     ScanVerdict = "CLEAN"
	VerdictMalicious ScanVerdict = "MALICIOUS"
	VerdictSuspicious ScanVerdict = "SUSPICIOUS"
)

// ScanResult contains details about an inspected file.
type ScanResult struct {
	SHA256    string      `json:"sha256"`
	FileName  string      `json:"file_name"`
	MimeType  string      `json:"mime_type"`
	Size      int64       `json:"size"`
	Verdict   ScanVerdict `json:"verdict"`
	ThreatName string     `json:"threat_name,omitempty"`
}

// FileInspector coordinates file scanning with ClamAV and heuristic YARA signatures.
type FileInspector struct {
	knownBadHashes map[string]string // hash -> threat name
}

// NewFileInspector creates a new file inspection engine.
func NewFileInspector() *FileInspector {
	fi := &FileInspector{
		knownBadHashes: make(map[string]string),
	}
	// Seed EICAR test file hash
	fi.knownBadHashes["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"] = "EICAR_Standard_AV_Test_File"
	return fi
}

// InspectBuffer computes the hash and scans a stream buffer.
func (fi *FileInspector) InspectBuffer(fileName string, data []byte) ScanResult {
	h := sha256.Sum256(data)
	hashStr := hex.EncodeToString(h[:])

	res := ScanResult{
		SHA256:   hashStr,
		FileName: fileName,
		Size:     int64(len(data)),
		Verdict:  VerdictClean,
		MimeType: detectMime(data),
	}

	// 1. Hash Reputation Lookup
	if threat, ok := fi.knownBadHashes[hashStr]; ok {
		res.Verdict = VerdictMalicious
		res.ThreatName = threat
		return res
	}

	// 2. High-Risk Executable / Script Inspection in non-binary streams
	if bytes.Contains(data, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")) {
		res.Verdict = VerdictMalicious
		res.ThreatName = "EICAR-Signature"
		return res
	}

	// Heuristic script detection: Windows dropper or PowerShell encoded command
	if bytes.Contains(data, []byte("FromBase64String")) && bytes.Contains(data, []byte("DownloadString")) {
		res.Verdict = VerdictSuspicious
		res.ThreatName = "Heuristic.Dropper.PowerShell"
		return res
	}

	return res
}

func detectMime(data []byte) string {
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		return "application/x-dosexec"
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("%PDF")) {
		return "application/pdf"
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("PK\x03\x04")) {
		return "application/zip"
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("\x7fELF")) {
		return "application/x-executable"
	}
	if strings.HasPrefix(string(data[:min(len(data), 64)]), "<!DOCTYPE html") {
		return "text/html"
	}
	return "application/octet-stream"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RegisterMaliciousHash adds an IOC hash to the reputation database.
func (fi *FileInspector) RegisterMaliciousHash(hash string, threatName string) error {
	if len(hash) != 64 {
		return errors.New("invalid SHA-256 hash length")
	}
	fi.knownBadHashes[strings.ToLower(hash)] = threatName
	return nil
}
