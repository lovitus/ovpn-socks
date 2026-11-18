// Package proxy provides a configurable SOCKS5 TCP CONNECT endpoint. All outbound
// connections are supplied by the caller; there is deliberately no default dialer.
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type DialFunc func(context.Context, string) (net.Conn, error)
type Server struct {
	listener net.Listener
	dial     DialFunc
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

func Listen(address string, dial DialFunc) (*Server, error) {
	if dial == nil {
		return nil, errors.New("SOCKS requires an isolated dial function")
	}
	if address == "" {
		address = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if host != "" && ip == nil {
		return nil, errors.New("SOCKS listener must use an IP address")
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{listener: ln, dial: dial, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}
func (s *Server) Addr() string { return s.listener.Addr().String() }
func (s *Server) Close() {
	s.cancel()
	s.listener.Close()
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer c.Close()
			defer func() { s.mu.Lock(); delete(s.conns, c); s.mu.Unlock() }()
			s.serve(c)
		}()
	}
}
func (s *Server) serve(c net.Conn) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [4]byte
	if _, err := io.ReadFull(c, h[:2]); err != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == 0 {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{5, 255})
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[2] != 0 {
		return
	}
	if h[1] != 1 {
		reply(c, 7, nil)
		return
	} // UDP ASSOCIATE and BIND are explicitly unsupported.
	var host string
	switch h[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		if _, err := io.ReadFull(c, h[:1]); err != nil || h[0] == 0 {
			return
		}
		b := make([]byte, int(h[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		reply(c, 8, nil)
		return
	}
	if _, err := io.ReadFull(c, h[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(h[:2])
	if port == 0 {
		reply(c, 2, nil)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
	up, err := s.dial(ctx, net.JoinHostPort(host, strconv.Itoa(int(port))))
	cancel()
	if err != nil {
		reply(c, 4, nil)
		return
	}
	defer up.Close()
	reply(c, 0, up.LocalAddr())
	c.SetDeadline(time.Time{})
	stop := context.AfterFunc(s.ctx, func() { up.Close(); c.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		io.Copy(up, c)
		if t, ok := up.(interface{ CloseWrite() error }); ok {
			t.CloseWrite()
		}
		close(done)
	}()
	io.Copy(c, up)
	c.Close()
	up.Close()
	<-done
}
func reply(c net.Conn, status byte, addr net.Addr) {
	b := []byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0}
	if a, ok := addr.(*net.TCPAddr); ok {
		if ip := a.IP.To4(); ip != nil {
			copy(b[4:8], ip)
			binary.BigEndian.PutUint16(b[8:], uint16(a.Port))
		}
	}
	c.Write(b)
}
