package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func awaitMetrics(t *testing.T, s *Server, check func(Metrics) bool) Metrics {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		m := s.Metrics()
		if check(m) {
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics timeout: %+v", m)
		}
		time.Sleep(time.Millisecond)
	}
}
func TestMetricsLivePayloadDirectionsAndConnections(t *testing.T) {
	peer := make(chan net.Conn, 1)
	s, err := Listen("127.0.0.1:0", func(context.Context, string) (net.Conn, error) { a, b := net.Pipe(); peer <- b; return a, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := request(t, s, 1, "metrics.invalid")
	defer c.Close()
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	p := <-peer
	defer p.Close()
	p.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("upload-seven"))
	buf := make([]byte, len("upload-seven"))
	if _, err := io.ReadFull(p, buf); err != nil {
		t.Fatal(err)
	}
	m := awaitMetrics(t, s, func(m Metrics) bool { return m.UploadBytes == uint64(len(buf)) })
	if m.DownloadBytes != 0 || m.ActiveConnections != 1 || m.PeakConnections != 1 || m.RequestsSucceeded != 1 || m.DialCount != 1 {
		t.Fatalf("live upload %+v", m)
	}
	go p.Write([]byte("down"))
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		t.Fatal(err)
	}
	awaitMetrics(t, s, func(m Metrics) bool { return m.DownloadBytes == 4 })
	c.Close()
	p.Close()
	s.Close()
	m = s.Metrics()
	if m.ActiveConnections != 0 || m.RequestsFailed != 0 || m.UploadBytes != uint64(len(buf)) || m.DownloadBytes != 4 || m.DialDurationMSTotal < m.DialDurationMSLast {
		t.Fatalf("final %+v", m)
	}
}
func TestMetricsFailedRequestsAndDial(t *testing.T) {
	s, err := Listen("127.0.0.1:0", func(context.Context, string) (net.Conn, error) { return nil, errors.New("offline") })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, command := range []byte{1, 3} {
		c := request(t, s, command, "offline.invalid")
		var response [10]byte
		io.ReadFull(c, response[:])
		c.Close()
	}
	s.Close()
	m := s.Metrics()
	if m.RequestsFailed != 2 || m.DialCount != 1 || m.RequestsSucceeded != 0 || m.UploadBytes != 0 || m.DownloadBytes != 0 {
		t.Fatalf("failed metrics %+v", m)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, io.ErrShortWrite }
func TestCountingWriterCountsOnlyWrittenBytes(t *testing.T) {
	var count atomic.Uint64
	w := countingWriter{shortWriter{}, &count}
	n, err := w.Write(make([]byte, 10))
	if n != 5 || err != io.ErrShortWrite || count.Load() != 5 {
		t.Fatalf("%d %v %d", n, err, count.Load())
	}
}
func TestCountersConcurrent(t *testing.T) {
	var m Counters
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				m.opened()
				m.upload.Add(3)
				m.download.Add(5)
				m.dialed(time.Millisecond)
				m.succeeded.Add(1)
				_ = m.snapshot()
				m.active.Add(-1)
			}
		}()
	}
	wg.Wait()
	v := m.snapshot()
	if v.ActiveConnections != 0 || v.UploadBytes != 48000 || v.DownloadBytes != 80000 || v.DialCount != 16000 || v.PeakConnections < 1 || v.PeakConnections > 16 {
		t.Fatalf("%+v", v)
	}
}
