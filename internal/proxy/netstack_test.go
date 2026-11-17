package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

type packetPipe struct{ in, out chan []byte }

func (p packetPipe) ReadDataPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-p.in:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (p packetPipe) WriteDataPacket(data []byte) error {
	select {
	case p.out <- append([]byte(nil), data...):
		return nil
	default:
		return errors.New("packet pipe full")
	}
}
func networkPair(t *testing.T) (*Network, *Network) {
	t.Helper()
	a, b := make(chan []byte, 1024), make(chan []byte, 1024)
	client, err := NewNetwork(packetPipe{a, b}, []netip.Addr{netip.MustParseAddr("10.123.0.2")}, []netip.AddrPort{netip.MustParseAddrPort("10.123.0.1:53")}, 1500)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewNetwork(packetPipe{b, a}, []netip.Addr{netip.MustParseAddr("10.123.0.1")}, nil, 1500)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}
func TestUserspaceTCPAndVPNDNS(t *testing.T) {
	client, server := networkPair(t)
	listen, err := gonet.ListenTCP(server.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 123, 0, 1}), Port: 8080}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	go func() {
		c, e := listen.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	local := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 123, 0, 1}), Port: 53}
	dns, err := gonet.DialUDP(server.stack, &local, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	queries := make(chan string, 8)
	go func() {
		for {
			q := make([]byte, 4096)
			size, addr, e := dns.ReadFrom(q)
			if e != nil {
				return
			}
			q = q[:size]
			if len(q) < 17 {
				continue
			}
			queries <- "VPN DNS"
			questionEnd := 12
			for questionEnd < len(q) && q[questionEnd] != 0 {
				questionEnd += int(q[questionEnd]) + 1
			}
			questionEnd++
			if questionEnd+4 > len(q) {
				continue
			}
			isA := binary.BigEndian.Uint16(q[questionEnd:]) == 1
			response := append([]byte(nil), q[:questionEnd+4]...)
			response[2], response[3] = 0x81, 0x80
			response[6], response[7] = 0, 0
			response[8], response[9], response[10], response[11] = 0, 0, 0, 0
			if isA {
				response[7] = 1
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 123, 0, 1)
			}
			dns.WriteTo(response, addr)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, "only-inside.invalid:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte("isolated")); err != nil {
		t.Fatal(err)
	}
	var result [8]byte
	if _, err = io.ReadFull(conn, result[:]); err != nil || string(result[:]) != "isolated" {
		t.Fatalf("echo %q: %v", result, err)
	}
	select {
	case <-queries:
	default:
		t.Fatal("VPN DNS was not queried")
	}
	// localhost must also go to VPN DNS, never the host hosts file.
	resolved, err := client.resolve(ctx, "localhost")
	if err != nil || len(resolved) != 1 || resolved[0].String() != "10.123.0.1" {
		t.Fatalf("host resolver influenced VPN DNS: %v %v", resolved, err)
	}
	client.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection survived network shutdown")
	}
	if _, err = client.Dial(ctx, "10.123.0.1:8080"); err == nil {
		t.Fatal("offline stack accepted a connection")
	}
}
func TestUserspaceNoHostFallback(t *testing.T) {
	pipe := packetPipe{make(chan []byte), make(chan []byte, 10)}
	n, err := NewNetwork(pipe, []netip.Addr{netip.MustParseAddr("10.123.0.2")}, nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err = n.Dial(ctx, "localhost:80"); err == nil {
		t.Fatal("resolved hostname with no VPN DNS")
	}
	if len(pipe.out) != 0 {
		t.Fatal("no-DNS lookup emitted traffic")
	}
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if _, err = n.Dial(ctx, host.Addr().String()); err == nil {
		t.Fatal("userspace dial reached host loopback")
	}
}
