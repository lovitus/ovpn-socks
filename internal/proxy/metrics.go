package proxy

import (
	"io"
	"sync/atomic"
	"time"
)

// Counters contains no destinations or payloads. All hot-path updates are atomic.
type Counters struct {
	upload, download                                  atomic.Uint64
	active, peak                                      atomic.Int64
	succeeded, failed, dialCount, dialTotal, dialLast atomic.Uint64
}

type Metrics struct {
	UploadBytes         uint64  `json:"upload_bytes"`
	DownloadBytes       uint64  `json:"download_bytes"`
	ActiveConnections   int64   `json:"active_connections"`
	PeakConnections     int64   `json:"peak_connections"`
	RequestsSucceeded   uint64  `json:"requests_succeeded"`
	RequestsFailed      uint64  `json:"requests_failed"`
	DialCount           uint64  `json:"dial_count"`
	DialDurationMSTotal float64 `json:"dial_duration_ms_total"`
	DialDurationMSLast  float64 `json:"dial_duration_ms_last"`
}

func (s *Server) Metrics() Metrics { return s.metrics.snapshot() }
func (m *Counters) snapshot() Metrics {
	return Metrics{UploadBytes: m.upload.Load(), DownloadBytes: m.download.Load(), ActiveConnections: m.active.Load(), PeakConnections: m.peak.Load(), RequestsSucceeded: m.succeeded.Load(), RequestsFailed: m.failed.Load(), DialCount: m.dialCount.Load(), DialDurationMSTotal: float64(m.dialTotal.Load()) / 1e6, DialDurationMSLast: float64(m.dialLast.Load()) / 1e6}
}
func (m *Counters) opened() {
	current := m.active.Add(1)
	for peak := m.peak.Load(); current > peak; peak = m.peak.Load() {
		if m.peak.CompareAndSwap(peak, current) {
			break
		}
	}
}
func (m *Counters) dialed(elapsed time.Duration) {
	m.dialCount.Add(1)
	m.dialTotal.Add(uint64(elapsed))
	m.dialLast.Store(uint64(elapsed))
}

// countingWriter counts only bytes successfully delivered. Wrapping the writer
// prevents io.Copy's ReaderFrom shortcut from hiding ongoing transfer updates.
// One wrapper is allocated per direction, never per packet or write.
type countingWriter struct {
	dst   io.Writer
	count *atomic.Uint64
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.count.Add(uint64(n))
	}
	return n, err
}
