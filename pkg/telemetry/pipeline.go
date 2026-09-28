// Package telemetry implements real-time flow telemetry, Prometheus metrics export,
// and session accounting for SentinelGate.
package telemetry

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// FlowRecord represents an L4/L7 network session flow.
type FlowRecord struct {
	ID        string    `json:"id"`
	StartTime time.Time `json:"start_time"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   int       `json:"src_port"`
	DstPort   int       `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	AppID     string    `json:"app_id"`
	BytesIn   uint64    `json:"bytes_in"`
	BytesOut  uint64    `json:"bytes_out"`
	PacketsIn uint64    `json:"packets_in"`
	PacketsOut uint64   `json:"packets_out"`
	Action    string    `json:"action"` // accept, drop, reject
	PolicyID  int       `json:"policy_id"`
}

// GatewayMetrics tracks global counters and instantaneous gauges.
type GatewayMetrics struct {
	ActiveSessions    int64
	TotalPacketsIn    uint64
	TotalPacketsOut   uint64
	TotalBytesIn      uint64
	TotalBytesOut     uint64
	TotalDrops        uint64
	TotalThreatAlerts uint64
}

// Pipeline ingests flow events and serves metrics.
type Pipeline struct {
	mu          sync.RWMutex
	metrics     GatewayMetrics
	recentFlows []FlowRecord
	maxFlows    int
}

// NewPipeline creates a new telemetry pipeline.
func NewPipeline(maxFlows int) *Pipeline {
	if maxFlows <= 0 {
		maxFlows = 10000
	}
	return &Pipeline{
		recentFlows: make([]FlowRecord, 0, maxFlows),
		maxFlows:    maxFlows,
	}
}

// RecordFlow ingests a flow record and updates global metrics atomically.
func (p *Pipeline) RecordFlow(f FlowRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.recentFlows) >= p.maxFlows {
		p.recentFlows = p.recentFlows[1:]
	}
	p.recentFlows = append(p.recentFlows, f)

	atomic.AddUint64(&p.metrics.TotalPacketsIn, f.PacketsIn)
	atomic.AddUint64(&p.metrics.TotalPacketsOut, f.PacketsOut)
	atomic.AddUint64(&p.metrics.TotalBytesIn, f.BytesIn)
	atomic.AddUint64(&p.metrics.TotalBytesOut, f.BytesOut)

	if f.Action == "drop" || f.Action == "reject" {
		atomic.AddUint64(&p.metrics.TotalDrops, 1)
	}
}

// IncrementActiveSessions updates the concurrent session count.
func (p *Pipeline) IncrementActiveSessions(delta int64) {
	atomic.AddInt64(&p.metrics.ActiveSessions, delta)
}

// GetRecentFlows returns a slice of the latest flow records.
func (p *Pipeline) GetRecentFlows(limit int) []FlowRecord {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if limit <= 0 || limit > len(p.recentFlows) {
		limit = len(p.recentFlows)
	}
	out := make([]FlowRecord, limit)
	copy(out, p.recentFlows[len(p.recentFlows)-limit:])
	return out
}

// GeneratePrometheusMetrics outputs Prometheus-compatible text format metrics.
func (p *Pipeline) GeneratePrometheusMetrics() string {
	var b bytes.Buffer

	b.WriteString("# HELP sentinelgate_active_sessions Number of active stateful conntrack sessions\n")
	b.WriteString("# TYPE sentinelgate_active_sessions gauge\n")
	b.WriteString(fmt.Sprintf("sentinelgate_active_sessions %d\n\n", atomic.LoadInt64(&p.metrics.ActiveSessions)))

	b.WriteString("# HELP sentinelgate_packets_total Total packets processed\n")
	b.WriteString("# TYPE sentinelgate_packets_total counter\n")
	b.WriteString(fmt.Sprintf("sentinelgate_packets_total{direction=\"in\"} %d\n", atomic.LoadUint64(&p.metrics.TotalPacketsIn)))
	b.WriteString(fmt.Sprintf("sentinelgate_packets_total{direction=\"out\"} %d\n\n", atomic.LoadUint64(&p.metrics.TotalPacketsOut)))

	b.WriteString("# HELP sentinelgate_bytes_total Total bytes processed\n")
	b.WriteString("# TYPE sentinelgate_bytes_total counter\n")
	b.WriteString(fmt.Sprintf("sentinelgate_bytes_total{direction=\"in\"} %d\n", atomic.LoadUint64(&p.metrics.TotalBytesIn)))
	b.WriteString(fmt.Sprintf("sentinelgate_bytes_total{direction=\"out\"} %d\n\n", atomic.LoadUint64(&p.metrics.TotalBytesOut)))

	b.WriteString("# HELP sentinelgate_drops_total Total dropped or rejected packets\n")
	b.WriteString("# TYPE sentinelgate_drops_total counter\n")
	b.WriteString(fmt.Sprintf("sentinelgate_drops_total %d\n", atomic.LoadUint64(&p.metrics.TotalDrops)))

	return b.String()
}
