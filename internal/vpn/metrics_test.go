package vpn

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestMetricsRingCapacityRetentionAndIsolation(t *testing.T) {
	now := time.Now()
	s := &Session{snapshot: Snapshot{State: "connected"}}
	start := now.Add(-time.Hour)
	s.metrics.started = start
	for i := 1; i <= 1800; i++ {
		s.sampleMetrics(start.Add(time.Duration(i) * metricsInterval))
	}
	v := s.Metrics()
	if len(v.History) != metricsCapacity || s.metrics.count != metricsCapacity {
		t.Fatalf("history %d stored %d", len(v.History), s.metrics.count)
	}
	for i, p := range v.History {
		if p.TimestampMS <= now.Add(-metricsRetention).UnixMilli() {
			t.Fatal("expired sample")
		}
		if i > 0 && p.TimestampMS <= v.History[i-1].TimestampMS {
			t.Fatal("unordered history")
		}
	}
	v.History[0].State = "mutated"
	if s.Metrics().History[0].State == "mutated" {
		t.Fatal("history alias")
	}
	s.mu.Lock()
	for i := range s.metrics.points {
		s.metrics.points[i].TimestampMS = now.Add(-metricsRetention - time.Second).UnixMilli()
	}
	s.mu.Unlock()
	if len(s.Metrics().History) != 0 {
		t.Fatal("stopped/stalled history did not expire")
	}
	t.Logf("fixed session metrics storage: %d bytes; point: %d bytes", unsafe.Sizeof(s.metrics), unsafe.Sizeof(MetricsPoint{}))
	if bytes := unsafe.Sizeof(s.metrics); bytes > 30*1024 {
		t.Fatalf("fixed memory exceeds 30KiB: %d", bytes)
	}
}
func TestMetricsSamplingIntervalAndOnlineTime(t *testing.T) {
	start := time.Now().Add(-time.Minute)
	s := &Session{snapshot: Snapshot{State: "connecting"}}
	s.metrics.started = start
	s.sampleMetrics(start.Add(time.Second))
	if s.metrics.count != 0 {
		t.Fatal("early sample")
	}
	s.sampleMetrics(start.Add(2 * time.Second))
	s.sampleMetrics(start.Add(3 * time.Second))
	if s.metrics.count != 1 {
		t.Fatal("sample interval")
	}
	s.setStateLocked("connected", start)
	s.setStateLocked("reconnecting", start.Add(10*time.Second))
	s.setStateLocked("connected", start.Add(20*time.Second))
	m := s.metricsCurrentLocked(start.Add(25 * time.Second))
	if m.OnlineDurationMS != 15000 || m.DisconnectCount != 1 || m.ConnectedSinceMS != start.Add(20*time.Second).UnixMilli() {
		t.Fatalf("online %+v", m)
	}
	s.setStateLocked("stopped", start.Add(30*time.Second))
	m = s.metricsCurrentLocked(start.Add(time.Hour))
	if m.OnlineDurationMS != 20000 || m.DisconnectCount != 1 || m.ConnectedSinceMS != 0 {
		t.Fatalf("stopped %+v", m)
	}
}
func TestSummaryAndSnapshotDoNotContainHistory(t *testing.T) {
	s := &Session{snapshot: Snapshot{Logs: []string{"secret-ish log"}, Routes: []string{"route"}}}
	s.metrics.started = time.Now().Add(-time.Second * 3)
	s.sampleMetrics(time.Now())
	for _, v := range []Snapshot{s.Snapshot(), s.Summary()} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "history") {
			t.Fatal("snapshot copied history")
		}
	}
	if s.Summary().Logs != nil || len(s.Snapshot().Logs) != 1 {
		t.Fatal("summary copied logs")
	}
}
func TestMetricsSamplingDoesNotAllocate(t *testing.T) {
	s := &Session{snapshot: Snapshot{State: "connected"}}
	now := time.Now()
	s.metrics.started = now
	allocs := testing.AllocsPerRun(100, func() {
		now = now.Add(metricsInterval)
		s.sampleMetrics(now)
	})
	if allocs != 0 {
		t.Fatalf("sampling allocates: %v", allocs)
	}
}

func TestMetricsConcurrentReadersAndSampler(t *testing.T) {
	s := &Session{snapshot: Snapshot{State: "connecting"}}
	s.metrics.started = time.Now().Add(-time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				s.Metrics()
				s.Snapshot()
				s.Summary()
			}
		}()
	}
	for i := 0; i < 500; i++ {
		s.sampleMetrics(s.metrics.started.Add(time.Duration(i+1) * metricsInterval))
		s.mu.Lock()
		s.setStateLocked("connected", time.Now())
		s.setStateLocked("reconnecting", time.Now())
		s.mu.Unlock()
	}
	wg.Wait()
}
