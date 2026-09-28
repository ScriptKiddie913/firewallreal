// Package tlsproxy provides Data Loss Prevention (DLP) stream inspection.
package tlsproxy

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// Luhn-checked Credit Card patterns
	visaRegex       = regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`)
	mastercardRegex = regexp.MustCompile(`\b5[1-5][0-9]{14}\b`)
	amexRegex       = regexp.MustCompile(`\b3[47][0-9]{13}\b`)

	// US Social Security Number (SSN)
	ssnRegex = regexp.MustCompile(`\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b`)

	// Private Cryptographic Keys
	privateKeyRegex = regexp.MustCompile(`-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY[^-]*-----`)
)

// DLPViolation represents a detected confidential data leak.
type DLPViolation struct {
	Type     string `json:"type"` // CreditCard, SSN, PrivateKey, Keyword
	Match    string `json:"match"`
	Severity string `json:"severity"` // HIGH, CRITICAL
}

// DLPEngine scans streams for confidential information leaks.
type DLPEngine struct {
	confidentialKeywords []string
}

// NewDLPEngine creates a new DLP engine instance.
func NewDLPEngine() *DLPEngine {
	return &DLPEngine{
		confidentialKeywords: []string{
			"CONFIDENTIAL", "STRICTLY PRIVATE", "SECRET",
			"INTERNAL USE ONLY", "DO NOT DISTRIBUTE",
		},
	}
}

// ScanStream inspects text or decoded buffers for data leakage.
func (d *DLPEngine) ScanStream(payload string) []DLPViolation {
	var violations []DLPViolation

	// 1. Private Key Detection (CRITICAL)
	if match := privateKeyRegex.FindString(payload); match != "" {
		violations = append(violations, DLPViolation{
			Type:     "PrivateKey",
			Match:    "-----BEGIN PRIVATE KEY-----",
			Severity: "CRITICAL",
		})
	}

	// 2. SSN Detection (HIGH)
	if match := ssnRegex.FindString(payload); match != "" {
		violations = append(violations, DLPViolation{
			Type:     "SSN",
			Match:    match[:3] + "-XX-XXXX",
			Severity: "HIGH",
		})
	}

	// 3. Credit Card Detection with Luhn validation
	for _, cc := range visaRegex.FindAllString(payload, -1) {
		if luhnCheck(cc) {
			violations = append(violations, DLPViolation{
				Type:     "CreditCard",
				Match:    "4XXX-XXXX-XXXX-" + cc[len(cc)-4:],
				Severity: "HIGH",
			})
			break
		}
	}
	for _, cc := range mastercardRegex.FindAllString(payload, -1) {
		if luhnCheck(cc) {
			violations = append(violations, DLPViolation{
				Type:     "CreditCard",
				Match:    "5XXX-XXXX-XXXX-" + cc[len(cc)-4:],
				Severity: "HIGH",
			})
			break
		}
	}

	// 4. Confidential Document Marking
	upper := strings.ToUpper(payload)
	for _, kw := range d.confidentialKeywords {
		if strings.Contains(upper, kw) {
			violations = append(violations, DLPViolation{
				Type:     "ConfidentialMarking",
				Match:    kw,
				Severity: "MEDIUM",
			})
			break
		}
	}

	return violations
}

// luhnCheck implements the Luhn algorithm for valid credit card checksums.
func luhnCheck(cardNo string) bool {
	sum := 0
	alternate := false

	for i := len(cardNo) - 1; i >= 0; i-- {
		digit, err := strconv.Atoi(string(cardNo[i]))
		if err != nil {
			return false
		}

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}
