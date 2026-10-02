//go:build linux && (amd64 || arm64)

package quic

import (
	"bytes"
	"cmp"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

type readMsg struct {
	data         []byte
	oob          []byte
	n, nn, flags int
	addr         net.Addr
}

// readMsgs reads with bc until it has count messages.
func readMsgs(t testing.TB, bc batchConn, count, bufSize int) []readMsg {
	ms := make([]ipv4.Message, batchSize)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, bufSize)}
		ms[i].OOB = make([]byte, oobBufferSize)
	}
	var got []readMsg
	for len(got) < count {
		n, err := bc.ReadBatch(ms, 0)
		require.NoError(t, err)
		for _, m := range ms[:n] {
			got = append(got, readMsg{
				data:  bytes.Clone(m.Buffers[0][:min(m.N, bufSize)]),
				oob:   bytes.Clone(m.OOB[:m.NN]),
				n:     m.N,
				nn:    m.NN,
				flags: m.Flags,
				addr:  m.Addr,
			})
		}
	}
	return got
}

// newSender opens a UDP socket on loopback that sends with an ECN mark.
func newSender(t testing.TB, network string) *net.UDPConn {
	ip := net.IPv4(127, 0, 0, 1)
	if network == "udp6" {
		ip = net.IPv6loopback
	}
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	rc, err := c.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, rc.Control(func(fd uintptr) {
		if network == "udp6" {
			require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, 3))
		} else {
			require.NoError(t, unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 2))
		}
	}))
	return c
}

func hasCmsg(oob []byte, level, typ int32) bool {
	for len(oob) > 0 {
		h, _, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return false
		}
		if h.Level == level && h.Type == typ {
			return true
		}
		oob = rest
	}
	return false
}

func TestMmsgConnReadsLikeXNet(t *testing.T) {
	cases := []struct {
		name    string
		network string   // network of the receiver
		bind    net.IP   // nil binds to the unspecified address
		senders []string // network of each sender
		order   []int    // sender of each send
		size    int      // payload size of each send
		bufSize int      // receive buffer size
		gsoSize int      // if set, each send is a GSO send of 3 segments
	}{
		{
			name:    "IPv4",
			network: "udp4",
			bind:    net.IPv4zero,
			senders: []string{"udp4"},
			order:   make([]int, 12),
		},
		{
			name:    "IPv6",
			network: "udp6",
			bind:    net.IPv6zero,
			senders: []string{"udp6"},
			order:   make([]int, 12),
		},
		{
			name:    "dual stack",
			network: "udp",
			senders: []string{"udp4", "udp6"},
			order:   []int{0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1},
		},
		{
			name:    "two senders alternate",
			network: "udp4",
			bind:    net.IPv4(127, 0, 0, 1),
			senders: []string{"udp4", "udp4"},
			order:   []int{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1},
		},
		{
			name:    "truncated packet",
			network: "udp4",
			bind:    net.IPv4(127, 0, 0, 1),
			senders: []string{"udp4"},
			order:   make([]int, 3),
			size:    200,
			bufSize: 100,
		},
		{
			name:    "GRO",
			network: "udp4",
			bind:    net.IPv4(127, 0, 0, 1),
			senders: []string{"udp4"},
			order:   make([]int, 4),
			size:    3 * 400,
			gsoSize: 400,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			size, bufSize := cmp.Or(tc.size, 100), cmp.Or(tc.bufSize, protocol.MaxPacketBufferSize)
			ln, err := net.ListenUDP(tc.network, &net.UDPAddr{IP: tc.bind})
			require.NoError(t, err)
			defer ln.Close()
			require.NoError(t, ln.SetReadDeadline(time.Now().Add(5*time.Second)))
			oc, err := newConn(ln, true)
			require.NoError(t, err)
			mc, ok := oc.batchConn.(*mmsgConn)
			require.True(t, ok)
			if tc.gsoSize > 0 {
				rc, err := ln.SyscallConn()
				require.NoError(t, err)
				var serr error
				require.NoError(t, rc.Control(func(fd uintptr) {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1)
				}))
				if serr != nil {
					t.Skipf("UDP_GRO not supported: %v", serr)
				}
			}

			senders := make([]*net.UDPConn, len(tc.senders))
			for i, network := range tc.senders {
				senders[i] = newSender(t, network)
			}
			send := func() {
				for i, s := range tc.order {
					dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ln.LocalAddr().(*net.UDPAddr).Port}
					if tc.senders[s] == "udp6" {
						dst.IP = net.IPv6loopback
					}
					var oob []byte
					if tc.gsoSize > 0 {
						oob = appendUDPSegmentSizeMsg(nil, uint16(tc.gsoSize))
					}
					_, _, err := senders[s].WriteMsgUDP(bytes.Repeat([]byte{byte(i)}, size), oob, dst)
					require.NoError(t, err)
				}
			}

			send()
			want := readMsgs(t, ipv4.NewPacketConn(ln), len(tc.order), bufSize)
			send()
			got := readMsgs(t, mc, len(tc.order), bufSize)

			for i := 1; i < len(got); i++ {
				if reflect.DeepEqual(got[i-1].addr, got[i].addr) {
					require.Same(t, got[i-1].addr, got[i].addr, "message %d", i)
				} else {
					require.NotSame(t, got[i-1].addr, got[i].addr, "message %d", i)
				}
			}
			// Packets from two senders can arrive in a different order.
			byData := func(a, b readMsg) int { return bytes.Compare(a.data, b.data) }
			slices.SortFunc(want, byData)
			slices.SortFunc(got, byData)
			for i := range want {
				require.NotZero(t, got[i].nn)
				require.Equal(t, want[i], got[i], "message %d", i)
			}
			if tc.bufSize > 0 {
				require.Equal(t, tc.bufSize, got[0].n)
				require.NotZero(t, got[0].flags&unix.MSG_TRUNC)
			}
			if tc.gsoSize > 0 {
				require.Equal(t, tc.size, got[0].n)
				require.True(t, hasCmsg(got[0].oob, unix.SOL_UDP, unix.UDP_GRO))
			}
		})
	}
}

func TestMmsgConnErrors(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*net.UDPConn)
		want  error
	}{
		{name: "closed", setup: func(c *net.UDPConn) { c.Close() }, want: net.ErrClosed},
		{name: "deadline", setup: func(c *net.UDPConn) { c.SetReadDeadline(time.Now().Add(-time.Second)) }, want: os.ErrDeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln := newUDPConnLocalhost(t)
			oc, err := newConn(ln, true)
			require.NoError(t, err)
			tc.setup(ln)
			ms := make([]ipv4.Message, 1)
			ms[0].Buffers = [][]byte{make([]byte, 10)}
			for _, bc := range []batchConn{ipv4.NewPacketConn(ln), oc.batchConn} {
				n, err := bc.ReadBatch(ms, 0)
				require.ErrorIs(t, err, tc.want)
				require.LessOrEqual(t, n, 0)
			}
		})
	}
}

func TestMmsghdrSize(t *testing.T) {
	// The kernel uses 64 bytes for struct mmsghdr on 64-bit platforms.
	require.EqualValues(t, 64, unsafe.Sizeof(mmsghdr{}))
}

func BenchmarkReadBatch(b *testing.B) {
	for _, senders := range []int{1, 2} {
		for _, reader := range []string{"x/net", "recvmmsg"} {
			b.Run(fmt.Sprintf("reader=%s/senders=%d", reader, senders), func(b *testing.B) {
				ln := newUDPConnLocalhost(b)
				require.NoError(b, ln.SetReadDeadline(time.Now().Add(time.Minute)))
				oc, err := newConn(ln, true)
				require.NoError(b, err)
				bc := oc.batchConn
				if reader == "x/net" {
					bc = ipv4.NewPacketConn(ln)
				}
				conns := make([]*net.UDPConn, senders)
				for i := range conns {
					conns[i] = newSender(b, "udp4")
				}
				ms := make([]ipv4.Message, batchSize)
				for i := range ms {
					ms[i].Buffers = [][]byte{make([]byte, protocol.MaxPacketBufferSize)}
					ms[i].OOB = make([]byte, oobBufferSize)
				}
				payload := make([]byte, 1200)
				dst := ln.LocalAddr()
				// 8 batches of 1200 B packets fit in the default socket buffer.
				const batches = 8
				var pkts int
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; {
					b.StopTimer()
					for j := range batches * batchSize {
						if _, err := conns[j%senders].WriteTo(payload, dst); err != nil {
							b.Fatal(err)
						}
					}
					b.StartTimer()
					for j := 0; j < batches && i < b.N; j, i = j+1, i+1 {
						n, err := bc.ReadBatch(ms, 0)
						if err != nil {
							b.Fatal(err)
						}
						pkts += n
					}
				}
				b.ReportMetric(float64(pkts)/float64(b.N), "pkts/op")
			})
		}
	}
}
