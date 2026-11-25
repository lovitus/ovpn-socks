package app

import (
	"errors"
	"net/http"
	"runtime/metrics"
	"time"

	"github.com/lovitus/ovpn-socks/internal/config"
	"github.com/lovitus/ovpn-socks/internal/routeexport"
)

type runtimeStats struct {
	UptimeMS       int64  `json:"uptime_ms"`
	HeapAllocBytes uint64 `json:"heap_alloc_bytes"`
	HeapSysBytes   uint64 `json:"heap_sys_bytes"`
	Goroutines     uint64 `json:"goroutines"`
	GCCycles       uint64 `json:"gc_cycles"`
}

// Read cheap runtime counters at most once every two seconds, regardless of the
// number of browser tabs. No heap walk, forced GC, disk writes or active probes.
func (s *Server) runtimeSnapshot() runtimeStats {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	now := time.Now()
	if s.runtimeAt.IsZero() || now.Sub(s.runtimeAt) >= 2*time.Second {
		names := []string{"/memory/classes/heap/objects:bytes", "/memory/classes/heap/free:bytes", "/memory/classes/heap/unused:bytes", "/memory/classes/heap/released:bytes", "/sched/goroutines:goroutines", "/gc/cycles/total:gc-cycles"}
		samples := make([]metrics.Sample, len(names))
		for i, name := range names {
			samples[i].Name = name
		}
		metrics.Read(samples)
		value := func(i int) uint64 {
			if samples[i].Value.Kind() == metrics.KindUint64 {
				return samples[i].Value.Uint64()
			}
			return 0
		}
		s.runtimeStats = runtimeStats{HeapAllocBytes: value(0), HeapSysBytes: value(0) + value(1) + value(2) + value(3), Goroutines: value(4), GCCycles: value(5)}
		s.runtimeAt = now
	}
	result := s.runtimeStats
	result.UptimeMS = now.Sub(s.startedAt).Milliseconds()
	return result
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, errors.New("method not allowed"))
		return
	}
	id := r.URL.Query().Get("profile")
	if id == "" {
		writeJSON(w, map[string]any{"current": nil, "history": []any{}, "sample_interval_ms": 2000, "retention_ms": 900000, "capacity": 450, "runtime": s.runtimeSnapshot()})
		return
	}
	if _, ok := s.store.Get(id); !ok {
		fail(w, 404, errors.New("配置不存在"))
		return
	}
	s.mu.Lock()
	session := s.sessions[id]
	s.mu.Unlock()
	if session == nil {
		writeJSON(w, map[string]any{"current": nil, "history": []any{}, "sample_interval_ms": 2000, "retention_ms": 900000, "capacity": 450, "runtime": s.runtimeSnapshot()})
		return
	}
	// Keep the history payload out of the regularly polled profile list.
	data := session.Metrics()
	writeJSON(w, struct {
		anyMetrics
		Runtime runtimeStats `json:"runtime"`
	}{anyMetrics: anyMetrics{Current: data.Current, History: data.History, SampleIntervalMS: data.SampleIntervalMS, RetentionMS: data.RetentionMS, Capacity: data.Capacity}, Runtime: s.runtimeSnapshot()})
}

type anyMetrics struct {
	Current          any   `json:"current"`
	History          any   `json:"history"`
	SampleIntervalMS int64 `json:"sample_interval_ms"`
	RetentionMS      int64 `json:"retention_ms"`
	Capacity         int   `json:"capacity"`
}

func (s *Server) exportRoutes(w http.ResponseWriter, r *http.Request, p config.Profile) {
	if p.EngineName() != "openvpn" {
		fail(w, 400, errors.New("路由转换仅适用于 OpenVPN 下发的网段"))
		return
	}
	var input struct {
		Format string `json:"format"`
		Host   string `json:"host"`
		Name   string `json:"name"`
	}
	if err := decode(w, r, &input); err != nil {
		fail(w, 400, err)
		return
	}
	if input.Format != "mihomo" && input.Format != "proxifier" && input.Format != "proxifier-hosts" {
		fail(w, 400, errors.New("不支持的规则格式"))
		return
	}
	if input.Name == "" {
		input.Name = p.Name
	}
	snapshot := s.describeSummary(p, true).Status
	result, err := routeexport.Convert(snapshot.Routes, routeexport.Options{ListenAddress: p.Listen, ProxyHost: input.Host, ProxyName: input.Name})
	if err != nil {
		fail(w, 400, err)
		return
	}
	if len(result.Prefixes) == 0 {
		fail(w, 400, errors.New("没有可转换的明确网段；请连接 VPN 获取路由。redirect-gateway 不会自动转换成全网代理规则。"))
		return
	}
	content, filename, mime := result.MihomoYAML, "ovpn-socks-mihomo.yaml", "application/yaml"
	if input.Format != "mihomo" {
		content, filename, mime = result.ProxifierHosts, "ovpn-socks-proxifier-hosts.txt", "text/plain"
	}
	writeJSON(w, map[string]any{"content": content, "filename": filename, "mime": mime, "warnings": result.Warnings})
}
