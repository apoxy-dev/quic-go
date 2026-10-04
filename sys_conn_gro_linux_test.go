//go:build linux

package quic

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

// appendCmsg appends one control message to b.
func appendCmsg(b []byte, level, typ int32, body []byte) []byte {
	start := len(b)
	b = append(b, make([]byte, unix.CmsgSpace(len(body)))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[start]))
	h.Level = level
	h.Type = typ
	h.SetLen(unix.CmsgLen(len(body)))
	copy(b[start+unix.CmsgSpace(0):], body)
	return b
}

func groCmsg(size int) []byte {
	return appendCmsg(nil, unix.IPPROTO_UDP, unix.UDP_GRO, binary.NativeEndian.AppendUint32(nil, uint32(size)))
}

func pktInfoCmsg4(addr netip.Addr, ifIndex uint32) []byte {
	// struct in_pktinfo: ipi_ifindex, ipi_spec_dst, ipi_addr.
	body := binary.NativeEndian.AppendUint32(nil, ifIndex)
	body = append(body, 0, 0, 0, 0)
	a := addr.As4()
	return appendCmsg(nil, unix.IPPROTO_IP, unix.IP_PKTINFO, append(body, a[:]...))
}

func pktInfoCmsg6(addr netip.Addr, ifIndex uint32) []byte {
	// struct in6_pktinfo: ipi6_addr, ipi6_ifindex.
	a := addr.As16()
	return appendCmsg(nil, unix.IPPROTO_IPV6, unix.IPV6_PKTINFO, binary.NativeEndian.AppendUint32(a[:], ifIndex))
}

// groMessage is one message of a fake read: the joined datagrams and the control messages.
type groMessage struct {
	payload []byte
	oob     []byte
	addr    net.Addr
}

// groReader returns one read with msgs, then net.ErrClosed.
type groReader struct {
	msgs []groMessage
	done bool
}

func (r *groReader) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	if r.done {
		return 0, net.ErrClosed
	}
	r.done = true
	for i, m := range r.msgs {
		ms[i].N = copy(ms[i].Buffers[0], m.payload)
		ms[i].NN = copy(ms[i].OOB, m.oob)
		ms[i].Addr = m.addr
	}
	return len(r.msgs), nil
}

// datagram returns size bytes of first. The first byte tells if it is a QUIC packet.
func datagram(first byte, size int) []byte {
	return bytes.Repeat([]byte{first}, size)
}

// wantDatagram is one datagram that ReadPacket must return.
type wantDatagram struct {
	data []byte
	ecn  protocol.ECN
	info netip.Addr
	addr net.Addr
}

func TestOOBConnSplitsJoinedDatagrams(t *testing.T) {
	addr4 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	addr6 := &net.UDPAddr{IP: net.IPv6loopback, Port: 1234}
	const quic, psp = 0x40, 0x04
	cases := []struct {
		name string
		msgs []groMessage
		// want are the datagrams of all messages, in order.
		want []wantDatagram
	}{
		{
			name: "one datagram, no GRO message",
			msgs: []groMessage{{payload: datagram(psp, 100), addr: addr4}},
			want: []wantDatagram{{data: datagram(psp, 100), addr: addr4}},
		},
		{
			name: "three datagrams",
			msgs: []groMessage{{payload: datagram(psp, 1200), oob: groCmsg(400), addr: addr4}},
			want: []wantDatagram{
				{data: datagram(psp, 400), addr: addr4},
				{data: datagram(psp, 400), addr: addr4},
				{data: datagram(psp, 400), addr: addr4},
			},
		},
		{
			name: "short last datagram",
			msgs: []groMessage{{payload: datagram(psp, 1000), oob: groCmsg(400), addr: addr4}},
			want: []wantDatagram{
				{data: datagram(psp, 400), addr: addr4},
				{data: datagram(psp, 400), addr: addr4},
				{data: datagram(psp, 200), addr: addr4},
			},
		},
		{
			name: "ECN and packet info on IPv4",
			msgs: []groMessage{{
				payload: datagram(psp, 800),
				oob:     append(append(appendIPv4ECNMsg(nil, protocol.ECT0), groCmsg(400)...), pktInfoCmsg4(netip.MustParseAddr("10.0.0.1"), 3)...),
				addr:    addr4,
			}},
			want: []wantDatagram{
				{data: datagram(psp, 400), ecn: protocol.ECT0, info: netip.MustParseAddr("10.0.0.1"), addr: addr4},
				{data: datagram(psp, 400), ecn: protocol.ECT0, info: netip.MustParseAddr("10.0.0.1"), addr: addr4},
			},
		},
		{
			name: "ECN and packet info on IPv6",
			msgs: []groMessage{{
				payload: datagram(psp, 800),
				oob:     append(append(appendIPv6ECNMsg(nil, protocol.ECNCE), groCmsg(400)...), pktInfoCmsg6(netip.MustParseAddr("fd00::1"), 5)...),
				addr:    addr6,
			}},
			want: []wantDatagram{
				{data: datagram(psp, 400), ecn: protocol.ECNCE, info: netip.MustParseAddr("fd00::1"), addr: addr6},
				{data: datagram(psp, 400), ecn: protocol.ECNCE, info: netip.MustParseAddr("fd00::1"), addr: addr6},
			},
		},
		{
			name: "QUIC datagrams get their own buffers",
			msgs: []groMessage{{payload: datagram(quic, 2400), oob: groCmsg(1200), addr: addr4}},
			want: []wantDatagram{
				{data: datagram(quic, 1200), addr: addr4},
				{data: datagram(quic, 1200), addr: addr4},
			},
		},
		{
			name: "QUIC and non-QUIC datagrams in one message",
			msgs: []groMessage{{payload: append(append(datagram(quic, 400), datagram(psp, 400)...), datagram(quic, 400)...), oob: groCmsg(400), addr: addr4}},
			want: []wantDatagram{
				{data: datagram(quic, 400), addr: addr4},
				{data: datagram(psp, 400), addr: addr4},
				{data: datagram(quic, 400), addr: addr4},
			},
		},
		{
			name: "two messages",
			msgs: []groMessage{
				{payload: datagram(psp, 800), oob: groCmsg(400), addr: addr4},
				{payload: datagram(psp, 100), addr: addr6},
			},
			want: []wantDatagram{
				{data: datagram(psp, 400), addr: addr4},
				{data: datagram(psp, 400), addr: addr4},
				{data: datagram(psp, 100), addr: addr6},
			},
		},
		{
			name: "empty datagram",
			msgs: []groMessage{{addr: addr4}},
			want: []wantDatagram{{data: []byte{}, addr: addr4}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newConn(newUDPConnLocalhost(t), true, false)
			require.NoError(t, err)
			c.cap.GRO = true
			c.batchConn = &groReader{msgs: tc.msgs}

			var rcvTime time.Time
			for i, want := range tc.want {
				require.True(t, c.buffered() || i == 0, "datagram %d", i)
				p, err := c.ReadPacket()
				require.NoError(t, err, "datagram %d", i)
				require.Equal(t, want.data, p.data, "datagram %d", i)
				require.Equal(t, want.ecn, p.ecn, "datagram %d", i)
				require.Equal(t, want.info, p.info.addr, "datagram %d", i)
				require.Same(t, want.addr, p.remoteAddr, "datagram %d", i)
				if i == 0 {
					rcvTime = p.rcvTime
				}
				require.Equal(t, rcvTime, p.rcvTime, "datagram %d", i)
				// A read buffer holds MaxGROPacketBufferSize. A QUIC datagram has a copy in a packet buffer.
				if isQUICPacket(p.data) {
					require.Equal(t, protocol.MaxPacketBufferSize, cap(p.buffer.Data), "datagram %d", i)
					require.Equal(t, 1, p.buffer.refCount, "datagram %d", i)
					p.buffer.Release()
				} else {
					require.Equal(t, protocol.MaxGROPacketBufferSize, cap(p.buffer.Data), "datagram %d", i)
					p.buffer.Decrement()
					p.buffer.MaybeRelease()
				}
			}
			require.False(t, c.buffered())
			// Every read buffer went back to the pool. The next read takes new ones.
			for i := range tc.msgs {
				require.Zero(t, c.buffers[i].refCount, "message %d", i)
			}
			_, err = c.ReadPacket()
			require.ErrorIs(t, err, net.ErrClosed)
		})
	}
}

// udpGRO returns the UDP_GRO socket option of c.
func udpGRO(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	require.NoError(t, err)
	var v int
	var serr error
	require.NoError(t, rc.Control(func(fd uintptr) {
		v, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
	}))
	if serr != nil {
		t.Skipf("UDP_GRO is not supported: %v", serr)
	}
	return v
}

// TestOOBConnGRO checks that only a conn with the opt-in sets UDP_GRO and reads into the large
// buffers.
func TestOOBConnGRO(t *testing.T) {
	cases := []struct {
		name    string
		gro     bool
		env     bool // QUIC_GO_DISABLE_GRO=true
		want    int  // The UDP_GRO socket option.
		bufSize int
	}{
		{name: "off", bufSize: protocol.MaxPacketBufferSize},
		{name: "on", gro: true, want: 1, bufSize: protocol.MaxGROPacketBufferSize},
		{name: "off by env", gro: true, env: true, bufSize: protocol.MaxPacketBufferSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env {
				t.Setenv("QUIC_GO_DISABLE_GRO", "true")
			}
			ln := newUDPConnLocalhost(t)
			c, err := newConn(ln, true, tc.gro)
			require.NoError(t, err)
			if tc.gro && !tc.env && !c.capabilities().GRO {
				t.Skip("UDP GRO is not supported")
			}
			require.Equal(t, tc.want == 1, c.capabilities().GRO)
			require.Equal(t, tc.want, udpGRO(t, ln))
			b := c.getReadBuffer()
			require.EqualValues(t, tc.bufSize, b.Cap())
			b.Release()
		})
	}
}

// TestTransportGRO starts a Transport with and without EnableGRO, sends one GSO datagram of three
// segments on loopback, and checks the socket option and that the handler gets each datagram.
func TestTransportGRO(t *testing.T) {
	for _, gro := range []bool{false, true} {
		t.Run(fmt.Sprintf("EnableGRO=%t", gro), func(t *testing.T) {
			ln := newUDPConnLocalhost(t)
			got := make(chan []byte, 64)
			ends := make(chan struct{}, 64)
			tr := &Transport{
				Conn:                 ln,
				EnableGRO:            gro,
				NonQUICPacketHandler: func(b []byte, _ net.Addr) { got <- bytes.Clone(b) },
				NonQUICBatchEnd:      func() { ends <- struct{}{} },
			}
			require.NoError(t, tr.Start())
			defer tr.Close()
			want := 0
			if gro {
				want = 1
			}
			require.Equal(t, want, udpGRO(t, ln))

			sender := newUDPConnLocalhost(t)
			payload := append(append(bytes.Repeat([]byte{0x04}, 500), bytes.Repeat([]byte{0x05}, 500)...), bytes.Repeat([]byte{0x06}, 300)...)
			_, _, err := sender.WriteMsgUDP(payload, appendUDPSegmentSizeMsg(nil, 500), ln.LocalAddr().(*net.UDPAddr))
			require.NoError(t, err)
			for _, want := range [][]byte{payload[:500], payload[500:1000], payload[1000:]} {
				select {
				case b := <-got:
					require.Equal(t, want, b)
				case <-time.After(time.Second):
					t.Fatal("timeout waiting for a datagram")
				}
			}
			select {
			case <-ends:
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for the batch end")
			}
			require.Empty(t, got)
		})
	}
}
