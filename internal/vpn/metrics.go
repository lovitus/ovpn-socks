package vpn

import (
	"time"

	"github.com/lovitus/ovpn-socks/internal/proxy"
)

const metricsCapacity = 450
const metricsInterval = 2 * time.Second
const metricsRetention = 15 * time.Minute

// MetricsSummary is live: payload counters do not wait for the sampling tick.
// Rates represent the latest completed sampling interval, not VPN wire traffic.
type MetricsSummary struct {
	proxy.Metrics
	TimestampMS            int64            `json:"timestamp_ms"`
	StartedAtMS            int64            `json:"started_at_ms"`
	ConnectedSinceMS       int64            `json:"connected_since_ms"`
	UploadBytesPerSecond   float64          `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond float64          `json:"download_bytes_per_second"`
	OnlineDurationMS       int64            `json:"online_duration_ms"`
	DisconnectCount        uint64           `json:"disconnect_count"`
	ReconnectCount         uint64           `json:"reconnect_count"`
	State                  string           `json:"state"`
	Reconnect              ReconnectMetrics `json:"reconnect"`
}
type ReconnectMetrics struct {
	Attempts            uint64 `json:"attempts"`
	Retries             uint64 `json:"retries"`
	Reconnects          uint64 `json:"reconnects"`
	ConsecutiveFailures uint64 `json:"consecutive_failures"`
	NextAttemptMS       int64  `json:"next_attempt_ms"`
	BackoffMS           int64  `json:"backoff_ms"`
	State               string `json:"state"`
}
type MetricsPoint struct {
	TimestampMS            int64   `json:"timestamp_ms"`
	UploadBytes            uint64  `json:"upload_bytes"`
	DownloadBytes          uint64  `json:"download_bytes"`
	UploadBytesPerSecond   float64 `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond float64 `json:"download_bytes_per_second"`
	ActiveConnections      int64   `json:"active_connections"`
	State                  string  `json:"state"`
}
type MetricsSnapshot struct {
	Current          MetricsSummary `json:"current"`
	History          []MetricsPoint `json:"history"`
	SampleIntervalMS int64          `json:"sample_interval_ms"`
	RetentionMS      int64          `json:"retention_ms"`
	Capacity         int            `json:"capacity"`
}

// Fixed storage: 450 * 64 = 28,800 bytes on 64-bit platforms, plus <512
// bytes of scalar accounting. Strings refer only to constant state names.
// No addresses, packet data, log copies, or per-sample heap allocations.
type sessionMetrics struct {
	points                   [metricsCapacity]MetricsPoint
	next, count              int
	started, connectedSince  time.Time
	online                   time.Duration
	disconnects              uint64
	lastSample               time.Time
	lastUpload, lastDownload uint64
	uploadRate, downloadRate float64
}

func unixMS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// setStateLocked accounts time at actual state changes, including stop/error.
func (s *Session) setStateLocked(state string, now time.Time) {
	old := s.snapshot.State
	if old == state {
		return
	}
	if old == "connected" && !s.metrics.connectedSince.IsZero() {
		s.metrics.online += now.Sub(s.metrics.connectedSince)
		s.metrics.connectedSince = time.Time{}
		if state != "stopped" {
			s.metrics.disconnects++
		}
	}
	if state == "connected" {
		s.metrics.connectedSince = now
	}
	s.snapshot.State = state
}
func (s *Session) metricsCurrentLocked(now time.Time) MetricsSummary {
	m := &s.metrics
	online := m.online
	if !m.connectedSince.IsZero() {
		online += now.Sub(m.connectedSince)
	}
	v := MetricsSummary{TimestampMS: now.UnixMilli(), StartedAtMS: unixMS(m.started), ConnectedSinceMS: unixMS(m.connectedSince), UploadBytesPerSecond: m.uploadRate, DownloadBytesPerSecond: m.downloadRate, OnlineDurationMS: online.Milliseconds(), DisconnectCount: m.disconnects, State: s.snapshot.State}
	if s.server != nil {
		v.Metrics = s.server.Metrics()
	}
	if s.client != nil {
		r := s.client.ReconnectStatus()
		v.Reconnect = ReconnectMetrics{Attempts: r.Attempts, Retries: r.Retries, Reconnects: r.Reconnects, ConsecutiveFailures: r.ConsecutiveFailures, NextAttemptMS: unixMS(r.NextAttempt), BackoffMS: r.Backoff.Milliseconds(), State: r.State}
		v.ReconnectCount = r.Retries
	}
	return v
}
func (s *Session) sampleMetrics(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := &s.metrics
	if m.lastSample.IsZero() {
		m.lastSample = m.started
		if m.lastSample.IsZero() {
			m.lastSample = now
		}
	}
	elapsed := now.Sub(m.lastSample)
	if elapsed < metricsInterval {
		return
	}
	var totals proxy.Metrics
	if s.server != nil {
		totals = s.server.Metrics()
	}
	m.uploadRate = float64(totals.UploadBytes-m.lastUpload) / elapsed.Seconds()
	m.downloadRate = float64(totals.DownloadBytes-m.lastDownload) / elapsed.Seconds()
	m.points[m.next] = MetricsPoint{TimestampMS: now.UnixMilli(), UploadBytes: totals.UploadBytes, DownloadBytes: totals.DownloadBytes, UploadBytesPerSecond: m.uploadRate, DownloadBytesPerSecond: m.downloadRate, ActiveConnections: totals.ActiveConnections, State: s.snapshot.State}
	m.next = (m.next + 1) % metricsCapacity
	if m.count < metricsCapacity {
		m.count++
	}
	m.lastSample = now
	m.lastUpload = totals.UploadBytes
	m.lastDownload = totals.DownloadBytes
}

// Metrics copies history only on demand and filters by wall-clock retention,
// including after a stalled ticker or a stopped session. The caller owns it.
func (s *Session) Metrics() MetricsSnapshot {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := MetricsSnapshot{Current: s.metricsCurrentLocked(now), History: make([]MetricsPoint, 0, s.metrics.count), SampleIntervalMS: metricsInterval.Milliseconds(), RetentionMS: metricsRetention.Milliseconds(), Capacity: metricsCapacity}
	first := (s.metrics.next - s.metrics.count + metricsCapacity) % metricsCapacity
	for i := 0; i < s.metrics.count; i++ {
		p := s.metrics.points[(first+i)%metricsCapacity]
		if p.TimestampMS > now.Add(-metricsRetention).UnixMilli() {
			v.History = append(v.History, p)
		}
	}
	return v
}
