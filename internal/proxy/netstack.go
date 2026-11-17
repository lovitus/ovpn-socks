package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// PacketTunnel exchanges raw IP packets with a VPN protocol engine, never an OS device.
type PacketTunnel interface {
	ReadDataPacket(context.Context) ([]byte, error)
	WriteDataPacket([]byte) error
}

// Network owns a separate TCP/IP stack per VPN session. There are no host socket
// dialers in this type: even DNS packets can leave only through PacketTunnel.
type Network struct {
	stack  *stack.Stack
	link   *channel.Endpoint
	tunnel PacketTunnel
	ips    []netip.Addr
	dns    []netip.AddrPort
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  map[*trackedConn]struct{}
	err    error
}

func NewNetwork(tunnel PacketTunnel, ips []netip.Addr, dns []netip.AddrPort, mtu uint32) (*Network, error) {
	if tunnel == nil || len(ips) == 0 {
		return nil, errors.New("VPN has no packet tunnel or assigned IP")
	}
	if mtu == 0 {
		mtu = 1500
	}
	if mtu < 576 || mtu > 65535 {
		return nil, errors.New("invalid VPN MTU")
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Network{tunnel: tunnel, ips: append([]netip.Addr(nil), ips...), dns: append([]netip.AddrPort(nil), dns...), ctx: ctx, cancel: cancel, conns: map[*trackedConn]struct{}{}}
	n.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}})
	n.link = channel.New(1024, mtu, "")
	if err := n.stack.CreateNIC(1, n.link); err != nil {
		n.Close()
		return nil, errors.New(err.String())
	}
	var routes []tcpip.Route
	has4, has6 := false, false
	for _, ip := range ips {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
			n.Close()
			return nil, errors.New("invalid assigned VPN IP")
		}
		protocol := ipv6.ProtocolNumber
		if ip.Is4() {
			protocol = ipv4.ProtocolNumber
			has4 = true
		} else {
			has6 = true
		}
		address := tcpip.AddrFromSlice(ip.AsSlice())
		if err := n.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: address.WithPrefix()}, stack.AddressProperties{}); err != nil {
			n.Close()
			return nil, errors.New(err.String())
		}
	}
	if has4 {
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if has6 {
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	n.stack.SetRouteTable(routes)
	n.wg.Add(2)
	go n.receive()
	go n.transmit()
	return n, nil
}
func (n *Network) receive() {
	defer n.wg.Done()
	for {
		data, err := n.tunnel.ReadDataPacket(n.ctx)
		if err != nil {
			n.fail(fmt.Errorf("VPN packet receive: %w", err))
			return
		}
		if len(data) == 0 {
			continue
		}
		var protocol tcpip.NetworkProtocolNumber
		switch data[0] >> 4 {
		case 4:
			protocol = ipv4.ProtocolNumber
		case 6:
			protocol = ipv6.ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		n.link.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
}
func (n *Network) transmit() {
	defer n.wg.Done()
	for {
		pkt := n.link.ReadContext(n.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		err := n.tunnel.WriteDataPacket(view.AsSlice())
		view.Release()
		pkt.DecRef()
		if err != nil {
			n.fail(fmt.Errorf("VPN packet transmit: %w", err))
			return
		}
	}
}
func (n *Network) fail(err error) {
	n.mu.Lock()
	if n.err == nil {
		n.err = err
	}
	n.mu.Unlock()
	n.cancel()
	n.closeConns()
}
func (n *Network) Err() error { n.mu.Lock(); defer n.mu.Unlock(); return n.err }
func (n *Network) closeConns() {
	n.mu.Lock()
	conns := make([]*trackedConn, 0, len(n.conns))
	for c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}
func (n *Network) Close() {
	n.once.Do(func() {
		n.cancel()
		n.closeConns()
		if n.link != nil {
			n.link.Close()
		}
		if n.stack != nil {
			n.stack.Close()
		}
		n.wg.Wait()
	})
}
func (n *Network) Dial(ctx context.Context, address string) (net.Conn, error) {
	if n.ctx.Err() != nil {
		return nil, errors.New("VPN is offline")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid destination port")
	}
	if strings.Contains(host, "%") {
		return nil, errors.New("scoped destination addresses are unsupported")
	}
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		if len(n.dns) == 0 {
			return nil, errors.New("VPN supplied no DNS server; hostname resolution is unavailable")
		}
		resolved, e := n.resolve(ctx, host)
		if e != nil {
			return nil, fmt.Errorf("VPN DNS: %w", e)
		}
		ips = resolved
	}
	var last error = errors.New("VPN has no address for destination family")
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			last = errors.New("local, multicast and unspecified destinations are forbidden")
			continue
		}
		conn, e := n.dialIP(ctx, "tcp", ip, uint16(port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, last
}
func (n *Network) dialIP(ctx context.Context, network string, ip netip.Addr, port uint16) (net.Conn, error) {
	if n.ctx.Err() != nil {
		return nil, errors.New("VPN is offline")
	}
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return nil, errors.New("invalid tunnel destination")
	}
	var source netip.Addr
	for _, local := range n.ips {
		if local.Is4() == ip.Is4() {
			source = local
			break
		}
	}
	if !source.IsValid() {
		return nil, errors.New("VPN has no IP for destination family")
	}
	protocol := ipv6.ProtocolNumber
	if ip.Is4() {
		protocol = ipv4.ProtocolNumber
	}
	local := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(source.AsSlice())}
	remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: port}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	stop := context.AfterFunc(n.ctx, cancel)
	defer stop()
	defer cancel()
	var conn net.Conn
	var err error
	if strings.HasPrefix(network, "udp") {
		conn, err = gonet.DialUDP(n.stack, &local, &remote, protocol)
	} else {
		conn, err = gonet.DialTCPWithBind(dialCtx, n.stack, local, remote, protocol)
	}
	if err != nil {
		return nil, err
	}
	wrapped := &trackedConn{Conn: conn, owner: n}
	n.mu.Lock()
	if n.ctx.Err() != nil {
		n.mu.Unlock()
		conn.Close()
		return nil, errors.New("VPN went offline")
	}
	n.conns[wrapped] = struct{}{}
	n.mu.Unlock()
	if packet, ok := conn.(net.PacketConn); ok {
		return &trackedPacketConn{trackedConn: wrapped, packet: packet}, nil
	}
	return wrapped, nil
}

// Resolver uses net.PacketConn to distinguish UDP datagrams from TCP DNS
// framing. Preserve that interface while tracking sockets for immediate close.
type trackedPacketConn struct {
	*trackedConn
	packet net.PacketConn
}

func (c *trackedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return c.packet.ReadFrom(b) }
func (c *trackedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(b, addr)
}

type trackedConn struct {
	net.Conn
	owner *Network
	once  sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.conns, c); c.owner.mu.Unlock() })
	return err
}
func (c *trackedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}
