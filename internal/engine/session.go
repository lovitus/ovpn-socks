package engine

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/lovitus/ovpn-socks/internal/vpn"
)

type Session struct {
	mu                             sync.Mutex
	opts                           Options
	cancel                         context.CancelFunc
	done                           chan struct{}
	status                         EngineStatus
	current                        record
	offset                         record
	state, failure                 string
	logs                           []string
	started, last, connected       time.Time
	online                         time.Duration
	disconnects, attempts, retries uint64
	reconnects                     uint64
	readyThisChild                 bool
	listenerTotals                 map[string]Listener
	nextAttempt                    time.Time
	backoff                        time.Duration
	history                        [450]vpn.MetricsPoint
	count, index                   int
	sampleTime                     time.Time
	sampleUp, sampleDown           uint64
	upRate, downRate               float64
}

// Start starts a real child immediately. A failed OS spawn is returned to the
// caller; subsequent child exits use the optional reconnect policy.
func Start(ctx context.Context, o Options) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p, err := prepare(o)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Session{opts: o, cancel: cancel, done: make(chan struct{}), started: time.Now(), state: "connecting", status: EngineStatus{Engine: o.Engine, State: "starting", ProcessRunning: true, Listeners: []Listener{}}}
	s.attempts = 1
	c, err := launch(ctx, p, o, "snapshot", s.accept)
	if err != nil {
		cancel()
		p.cleanup()
		return nil, err
	}
	s.mu.Lock()
	s.logLocked("managed engine started")
	s.mu.Unlock()
	go s.run(ctx, p, c)
	return s, nil
}
func (s *Session) logLocked(message string) {
	if len(s.logs) >= 100 {
		copy(s.logs, s.logs[1:])
		s.logs = s.logs[:99]
	}
	s.logs = append(s.logs, time.Now().UTC().Format(time.RFC3339)+" "+message)
}
func (s *Session) setStateLocked(state string, now time.Time) {
	if s.state == state {
		return
	}
	if !s.connected.IsZero() {
		s.online += now.Sub(s.connected)
		s.connected = time.Time{}
		if state != "stopped" {
			s.disconnects++
		}
	}
	if state == "connected" {
		s.connected = now
	}
	s.state = state
}
func (s *Session) accept(r record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Type == "error" {
		s.failure = safeDiagnostic(r)
		s.status.State = "failed"
		s.status.MetricsAvailable = false
		for i := range s.status.Listeners {
			s.status.Listeners[i].State = "unknown"
			s.status.Listeners[i].MetricsAvailable = false
		}
		s.setStateLocked("error", time.Now())
		return
	}
	// A regression is invalid in one process; never let it underflow rates.
	if r.UploadBytes < s.current.UploadBytes || r.DownloadBytes < s.current.DownloadBytes || r.TotalConnections < s.current.TotalConnections || r.FailedConnections < s.current.FailedConnections {
		return
	}
	now := time.Now()
	// Freshness uses both arrival and producer clock, allowing bounded clock skew.
	if r.TimestampMS <= 0 || r.TimestampMS < now.Add(-freshness).UnixMilli() || r.TimestampMS > now.Add(30*time.Second).UnixMilli() {
		return
	}
	s.current = r
	s.last = now
	s.status.State = r.State
	s.status.CounterScope = r.CounterScope
	s.status.ConnectionScope = r.ConnectionScope
	s.failure = ""
	s.status.Listeners = r.Listeners
	s.status.MetricsAvailable = r.MetricsAvailable
	switch r.State {
	case "connected", "ready":
		if !s.readyThisChild {
			s.readyThisChild = true
			if s.retries > 0 {
				s.reconnects++
			}
		}
		s.setStateLocked("connected", now)
	case "failed":
		s.setStateLocked("error", now)
	case "degraded":
		s.setStateLocked("degraded", now)
	case "stopped":
		s.setStateLocked("stopped", now)
	default:
		s.setStateLocked("connecting", now)
	}
}
func (s *Session) refreshLocked(now time.Time) {
	s.status.Fresh = s.status.ProcessRunning && !s.last.IsZero() && now.Sub(s.last) <= freshness
	if !s.status.Fresh && s.status.ProcessRunning && !s.last.IsZero() {
		s.status.State = "degraded"
		s.setStateLocked("degraded", now)
	}
}
func (s *Session) endChildLocked(now time.Time) {
	s.offset.UploadBytes += s.current.UploadBytes
	s.offset.DownloadBytes += s.current.DownloadBytes
	s.offset.TotalConnections += s.current.TotalConnections
	s.offset.FailedConnections += s.current.FailedConnections
	if s.listenerTotals == nil {
		s.listenerTotals = make(map[string]Listener)
	}
	for _, l := range s.current.Listeners {
		total, exists := s.listenerTotals[l.ID]
		if !exists && len(s.listenerTotals) >= 256 {
			continue
		}
		total.UploadBytes += l.UploadBytes
		total.DownloadBytes += l.DownloadBytes
		total.TotalConnections += l.TotalConnections
		total.FailedConnections += l.FailedConnections
		s.listenerTotals[l.ID] = total
	}
	s.current = record{}
	s.status.ProcessRunning = false
	s.status.Fresh = false
	s.status.MetricsAvailable = false
	for i := range s.status.Listeners {
		s.status.Listeners[i].UploadBytes = 0
		s.status.Listeners[i].DownloadBytes = 0
		s.status.Listeners[i].TotalConnections = 0
		s.status.Listeners[i].FailedConnections = 0
		s.status.Listeners[i].State = "closed"
		s.status.Listeners[i].ActiveConnections = 0
		s.status.Listeners[i].MetricsAvailable = false
	}
	s.setStateLocked("error", now)
	s.status.State = "failed"
	if s.failure == "" {
		s.failure = "managed engine exited"
	}
	s.logLocked(s.failure)
}
func (s *Session) run(ctx context.Context, p prepared, c *child) {
	defer close(s.done)
	defer func() { p.cleanup() }()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	started := time.Now()
	delay := time.Second
	for {
		select {
		case <-ctx.Done():
			c.kill()
			<-c.done
			s.mu.Lock()
			s.setStateLocked("stopped", time.Now())
			s.endChildLocked(time.Now())
			s.failure = ""
			s.status.State = "stopped"
			s.setStateLocked("stopped", time.Now())
			s.logLocked("managed engine stopped")
			s.mu.Unlock()
			return
		case now := <-tick.C:
			s.sample(now)
		case <-c.done:
			p.cleanup()
			p = prepared{}
			s.mu.Lock()
			s.endChildLocked(time.Now())
			s.mu.Unlock()
			if !s.opts.AutoReconnect {
				return
			}
			if time.Since(started) >= 60*time.Second {
				delay = time.Second
			}
			for {
				wait := delay + time.Duration(rand.Int64N(int64(delay/4)+1))
				if wait > 60*time.Second {
					wait = 60 * time.Second
				}
				s.mu.Lock()
				s.backoff = wait
				s.nextAttempt = time.Now().Add(wait)
				s.setStateLocked("reconnecting", time.Now())
				s.status.State = "connecting"
				s.mu.Unlock()
				timer := time.NewTimer(wait)
				waiting := true
				for waiting {
					select {
					case <-ctx.Done():
						timer.Stop()
						s.mu.Lock()
						s.status.State = "stopped"
						s.failure = ""
						s.nextAttempt = time.Time{}
						s.setStateLocked("stopped", time.Now())
						s.mu.Unlock()
						return
					case now := <-tick.C:
						s.sample(now)
					case <-timer.C:
						waiting = false
					}
				}
				s.mu.Lock()
				s.attempts++
				s.retries++
				s.status.Restarts = s.retries
				s.last = time.Time{}
				s.readyThisChild = false
				s.nextAttempt = time.Time{}
				s.status.ProcessRunning = true
				s.status.State = "starting"
				s.failure = ""
				s.mu.Unlock()
				var err error
				p, err = prepare(s.opts)
				if err == nil {
					c, err = launch(ctx, p, s.opts, "snapshot", s.accept)
				}
				if err != nil {
					p.cleanup()
					p = prepared{}
				}
				delay *= 2
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				if err == nil {
					started = time.Now()
					break
				}
				s.mu.Lock()
				s.status.ProcessRunning = false
				s.failure = "managed engine restart failed"
				s.logLocked(s.failure)
				s.mu.Unlock()
			}
		}
	}
}
func (s *Session) Stop() {
	s.cancel()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.State = "stopped"
	s.failure = ""
	s.nextAttempt = time.Time{}
	s.setStateLocked("stopped", time.Now())
}
func (s *Session) EngineStatus() EngineStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	v := s.status
	v.Listeners = append([]Listener{}, s.status.Listeners...)
	for i := range v.Listeners {
		total := s.listenerTotals[v.Listeners[i].ID]
		v.Listeners[i].UploadBytes += total.UploadBytes
		v.Listeners[i].DownloadBytes += total.DownloadBytes
		v.Listeners[i].TotalConnections += total.TotalConnections
		v.Listeners[i].FailedConnections += total.FailedConnections
	}
	if !s.last.IsZero() {
		v.LastTelemetryMS = s.last.UnixMilli()
	}
	v.TotalConnections = s.offset.TotalConnections + s.current.TotalConnections
	v.FailedConnections = s.offset.FailedConnections + s.current.FailedConnections
	if !v.Fresh {
		v.MetricsAvailable = false
		for i := range v.Listeners {
			if v.Listeners[i].State == "listening" {
				v.Listeners[i].State = "unknown"
			}
			v.Listeners[i].MetricsAvailable = false
			v.Listeners[i].ActiveConnections = 0
		}
	}
	return v
}
func (s *Session) Snapshot() vpn.Snapshot { return s.snapshot(true) }
func (s *Session) Summary() vpn.Snapshot  { return s.snapshot(false) }
func (s *Session) snapshot(logs bool) vpn.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	v := vpn.Snapshot{ID: s.opts.ID, State: s.state, Error: s.failure, Routes: []string{}, DNS: []string{}, Metrics: s.metricsLocked(time.Now())}
	if logs {
		v.Logs = append([]string{}, s.logs...)
	}
	for _, l := range s.status.Listeners {
		if l.Scope == "local" {
			v.Listen = l.Address
			if l.ActualAddress != "" {
				v.Listen = l.ActualAddress
			}
			break
		}
	}
	return v
}
func (s *Session) metricsLocked(now time.Time) vpn.MetricsSummary {
	online := s.online
	if !s.connected.IsZero() {
		online += now.Sub(s.connected)
	}
	v := vpn.MetricsSummary{TimestampMS: now.UnixMilli(), StartedAtMS: s.started.UnixMilli(), State: s.state, OnlineDurationMS: online.Milliseconds(), DisconnectCount: s.disconnects, ReconnectCount: s.retries, UploadBytesPerSecond: s.upRate, DownloadBytesPerSecond: s.downRate}
	if !s.connected.IsZero() {
		v.ConnectedSinceMS = s.connected.UnixMilli()
	}
	v.UploadBytes = s.offset.UploadBytes + s.current.UploadBytes
	v.DownloadBytes = s.offset.DownloadBytes + s.current.DownloadBytes
	if s.status.Fresh {
		v.ActiveConnections = s.current.ActiveConnections
	} else {
		v.UploadBytesPerSecond = 0
		v.DownloadBytesPerSecond = 0
	}
	// Native accepted-flow counters are intentionally not relabeled SOCKS requests.
	v.Reconnect = vpn.ReconnectMetrics{Attempts: s.attempts, Retries: s.retries, Reconnects: s.reconnects, BackoffMS: s.backoff.Milliseconds(), State: s.state}
	if !s.nextAttempt.IsZero() {
		v.Reconnect.NextAttemptMS = s.nextAttempt.UnixMilli()
	}
	return v
}
func (s *Session) sample(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(now)
	if !s.status.Fresh || !s.status.MetricsAvailable {
		s.upRate = 0
		s.downRate = 0
		return
	}
	m := s.metricsLocked(now)
	prev := s.sampleTime
	if prev.IsZero() {
		prev = s.started
	}
	elapsed := now.Sub(prev).Seconds()
	if elapsed <= 0 {
		return
	}
	s.upRate = float64(m.UploadBytes-s.sampleUp) / elapsed
	s.downRate = float64(m.DownloadBytes-s.sampleDown) / elapsed
	if !s.status.Fresh {
		s.upRate = 0
		s.downRate = 0
	}
	s.history[s.index] = vpn.MetricsPoint{TimestampMS: now.UnixMilli(), UploadBytes: m.UploadBytes, DownloadBytes: m.DownloadBytes, UploadBytesPerSecond: s.upRate, DownloadBytesPerSecond: s.downRate, ActiveConnections: m.ActiveConnections, State: s.state}
	s.index = (s.index + 1) % len(s.history)
	if s.count < len(s.history) {
		s.count++
	}
	s.sampleTime = now
	s.sampleUp = m.UploadBytes
	s.sampleDown = m.DownloadBytes
}
func (s *Session) Metrics() vpn.MetricsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.refreshLocked(now)
	v := vpn.MetricsSnapshot{Current: s.metricsLocked(now), SampleIntervalMS: 2000, RetentionMS: 900000, Capacity: 450, History: make([]vpn.MetricsPoint, 0, s.count)}
	first := (s.index - s.count + len(s.history)) % len(s.history)
	for i := 0; i < s.count; i++ {
		p := s.history[(first+i)%len(s.history)]
		if p.TimestampMS > now.Add(-15*time.Minute).UnixMilli() {
			v.History = append(v.History, p)
		}
	}
	return v
}
