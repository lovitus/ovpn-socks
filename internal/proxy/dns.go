package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// resolve deliberately does not call net.Resolver: even with a custom Dial it
// can consult the host hosts file and search domains. Queries here are absolute
// DNS wire messages sent only through the per-session userspace stack.
func (n *Network) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	var last error
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		supported := false
		for _, local := range n.ips {
			if local.Is4() == (typ == dnsmessage.TypeA) {
				supported = true
				break
			}
		}
		if !supported {
			continue
		}
		for _, server := range n.dns {
			answer, e := n.queryDNS(ctx, server, name, typ)
			if e == nil {
				addresses = append(addresses, answer...)
				break
			}
			last = e
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}
	if len(addresses) == 0 {
		if last != nil {
			return nil, last
		}
		return nil, errors.New("VPN DNS returned no address for destination")
	}
	return addresses, nil
}
func (n *Network) queryDNS(ctx context.Context, server netip.AddrPort, name dnsmessage.Name, typ dnsmessage.Type) ([]netip.Addr, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	question := dnsmessage.Question{Name: name, Type: typ, Class: dnsmessage.ClassINET}
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
	wire, err := request.Pack()
	if err != nil {
		return nil, err
	}
	for _, network := range []string{"udp", "tcp"} {
		conn, err := n.dialIP(ctx, network, server.Addr(), server.Port())
		if err != nil {
			return nil, err
		}
		deadline := time.Now().Add(3 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		conn.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		response := make([]byte, 65535)
		if network == "tcp" {
			payload := append([]byte{byte(len(wire) >> 8), byte(len(wire))}, wire...)
			err = writeAll(conn, payload)
			if err == nil {
				var length [2]byte
				_, err = io.ReadFull(conn, length[:])
				if err == nil {
					size := int(binary.BigEndian.Uint16(length[:]))
					response = response[:size]
					_, err = io.ReadFull(conn, response)
				}
			}
		} else {
			err = writeAll(conn, wire)
			if err == nil {
				var count int
				count, err = conn.Read(response)
				response = response[:count]
			}
		}
		stop()
		conn.Close()
		if err != nil {
			return nil, fmt.Errorf("DNS %s over VPN: %w", server, err)
		}
		var message dnsmessage.Message
		if err = message.Unpack(response); err != nil {
			return nil, fmt.Errorf("invalid VPN DNS response: %w", err)
		}
		if message.ID != id || !message.Response || message.OpCode != 0 || len(message.Questions) != 1 || message.Questions[0].Type != typ || message.Questions[0].Class != dnsmessage.ClassINET || !strings.EqualFold(message.Questions[0].Name.String(), name.String()) {
			return nil, errors.New("VPN DNS response does not match query")
		}
		if message.Truncated {
			if network == "udp" {
				continue
			}
			return nil, errors.New("VPN DNS TCP response is truncated")
		}
		if message.RCode != dnsmessage.RCodeSuccess {
			return nil, fmt.Errorf("VPN DNS returned %s", message.RCode)
		}
		// Only accept A/AAAA records on the answer's validated CNAME chain; unrelated
		// additional/answer addresses are not eligible connection destinations.
		names := map[string]bool{strings.ToLower(name.String()): true}
		for i := 0; i < 16; i++ {
			changed := false
			for _, answer := range message.Answers {
				if !names[strings.ToLower(answer.Header.Name.String())] || answer.Header.Class != dnsmessage.ClassINET {
					continue
				}
				if cname, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
					target := strings.ToLower(cname.CNAME.String())
					if !names[target] {
						names[target] = true
						changed = true
					}
				}
			}
			if !changed {
				break
			}
		}
		var ips []netip.Addr
		for _, answer := range message.Answers {
			if !names[strings.ToLower(answer.Header.Name.String())] || answer.Header.Class != dnsmessage.ClassINET {
				continue
			}
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				if typ == dnsmessage.TypeA {
					ips = append(ips, netip.AddrFrom4(body.A))
				}
			case *dnsmessage.AAAAResource:
				if typ == dnsmessage.TypeAAAA {
					ips = append(ips, netip.AddrFrom16(body.AAAA))
				}
			}
		}
		return ips, nil
	}
	return nil, errors.New("VPN DNS query failed")
}
func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}
