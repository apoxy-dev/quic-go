package self_test

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

// countECN counts the ECN codepoints of the 1-RTT packets that a connection received.
func countECN(r *events.Recorder) map[qlog.ECN]int {
	counts := make(map[qlog.ECN]int)
	for _, ev := range r.Events(qlog.PacketReceived{}) {
		if p := ev.(qlog.PacketReceived); p.Header.PacketType == qlog.PacketType1RTT {
			counts[p.ECN]++
		}
	}
	return counts
}

// inBandECNConn is a quic.ECNPacketConn on a UDP socket. It sends the ECN bits
// in the first byte of each datagram, so a test can see them on all platforms.
type inBandECNConn struct {
	udp *net.UDPConn
	// dropRead makes ReadFromECN report Not-ECT for each packet.
	dropRead bool

	mu      sync.Mutex
	written []uint8
}

var _ quic.ECNPacketConn = &inBandECNConn{}

func (c *inBandECNConn) ReadFromECN(b []byte) (int, net.Addr, uint8, error) {
	buf := make([]byte, len(b)+1)
	for {
		n, addr, err := c.udp.ReadFrom(buf)
		if err != nil {
			return 0, nil, 0, err
		}
		if n == 0 {
			continue
		}
		ecn := buf[0]
		if c.dropRead {
			ecn = 0
		}
		return copy(b, buf[1:n]), addr, ecn, nil
	}
}

func (c *inBandECNConn) WriteToECN(b []byte, addr net.Addr, ecn uint8) (int, error) {
	c.mu.Lock()
	c.written = append(c.written, ecn)
	c.mu.Unlock()
	n, err := c.udp.WriteTo(append([]byte{ecn}, b...), addr)
	return max(n-1, 0), err
}

// lastWritten returns the ECN bits of the last n packets that the conn wrote.
func (c *inBandECNConn) lastWritten(n int) []uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint8(nil), c.written[max(len(c.written)-n, 0):]...)
}

// inBandGSOConn is an inBandECNConn that also takes GSO batches. It sends each packet of a
// batch as its own datagram, and records the number of packets of each batch.
type inBandGSOConn struct {
	*inBandECNConn

	mu      sync.Mutex
	batches []int
}

var _ quic.GSOPacketConn = &inBandGSOConn{}

func (c *inBandGSOConn) WriteToGSO(b []byte, addr net.Addr, gsoSize uint16, ecn uint8) (int, error) {
	c.mu.Lock()
	c.batches = append(c.batches, (len(b)+int(gsoSize)-1)/int(gsoSize))
	c.mu.Unlock()
	var n int
	for p := b; len(p) > 0; p = p[min(len(p), int(gsoSize)):] {
		m, err := c.WriteToECN(p[:min(len(p), int(gsoSize))], addr, ecn)
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// largestBatch returns the most packets of one batch.
func (c *inBandGSOConn) largestBatch() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Max(append([]int{0}, c.batches...))
}

func (c *inBandECNConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, _, err := c.ReadFromECN(b)
	return n, addr, err
}

func (c *inBandECNConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.WriteToECN(b, addr, 0)
}

func (c *inBandECNConn) Close() error                       { return c.udp.Close() }
func (c *inBandECNConn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *inBandECNConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *inBandECNConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *inBandECNConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

func TestECNPacketConn(t *testing.T) {
	const ect0, notECT = 0b10, 0b00
	cases := []struct {
		name     string
		dropRead bool
		// gso makes each conn a GSOPacketConn.
		gso bool
		// wantLast is the ECN bits of the last packets that each side writes.
		wantLast uint8
	}{
		// The peer reads ECT(0) and acknowledges it, so ECN validation passes.
		{name: "bits read", wantLast: ect0},
		// The peer reads Not-ECT, so ECN validation fails and the sender stops marking.
		{name: "bits lost", dropRead: true, wantLast: notECT},
		// ECN validation passes only if each packet of a batch has the ECN bits that the sender
		// counted for it.
		{name: "bits read, GSO", gso: true, wantLast: ect0},
		{name: "bits lost, GSO", dropRead: true, gso: true, wantLast: notECT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fromClient, fromServer events.Recorder
			serverConn := &inBandECNConn{udp: newUDPConnLocalhost(t), dropRead: tc.dropRead}
			clientConn := &inBandECNConn{udp: newUDPConnLocalhost(t), dropRead: tc.dropRead}
			var serverPC, clientPC net.PacketConn = serverConn, clientConn
			var serverGSO, clientGSO *inBandGSOConn
			if tc.gso {
				serverGSO, clientGSO = &inBandGSOConn{inBandECNConn: serverConn}, &inBandGSOConn{inBandECNConn: clientConn}
				serverPC, clientPC = serverGSO, clientGSO
			}
			serverTr := &quic.Transport{Conn: serverPC}
			defer serverTr.Close()
			clientTr := &quic.Transport{Conn: clientPC}
			defer clientTr.Close()

			ln, err := serverTr.Listen(getTLSConfig(), getQuicConfig(&quic.Config{Tracer: newTracer(&fromClient)}))
			require.NoError(t, err)
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
			defer cancel()
			conn, err := clientTr.Dial(ctx, ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{Tracer: newTracer(&fromServer)}))
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			sconn, err := ln.Accept(ctx)
			require.NoError(t, err)
			defer sconn.CloseWithError(0, "")

			// The server echoes 100 KB, so that both sides send many 1-RTT packets.
			go func() {
				str, err := sconn.AcceptStream(ctx)
				if err != nil {
					return
				}
				_, _ = io.Copy(str, str)
				str.Close()
			}()
			str, err := conn.OpenStream()
			require.NoError(t, err)
			data := make([]byte, 100<<10)
			written := make(chan error, 1)
			go func() {
				_, err := str.Write(data)
				str.Close()
				written <- err
			}()
			got, err := io.ReadAll(str)
			require.NoError(t, err)
			require.NoError(t, <-written)
			require.Len(t, got, len(data))

			for _, side := range []struct {
				name string
				rcvd *events.Recorder
				conn *inBandECNConn
			}{{"client", &fromClient, clientConn}, {"server", &fromServer, serverConn}} {
				if tc.dropRead {
					require.Zero(t, countECN(side.rcvd)[qlog.ECT0], "the peer of the %s read ECT(0)", side.name)
				} else {
					require.NotZero(t, countECN(side.rcvd)[qlog.ECT0], "the peer of the %s read no ECT(0)", side.name)
				}
				for _, bits := range side.conn.lastWritten(5) {
					require.Equal(t, tc.wantLast, bits, "ECN bits of a late packet of the %s", side.name)
				}
			}
			// A conn with GSO gets batches of many packets. A conn without it gets single writes.
			require.Equal(t, tc.gso, conn.ConnectionState().GSO)
			require.Equal(t, tc.gso, sconn.ConnectionState().GSO)
			if tc.gso {
				require.Greater(t, clientGSO.largestBatch(), 1, "the client sent no batch of many packets")
				require.Greater(t, serverGSO.largestBatch(), 1, "the server sent no batch of many packets")
			}
		})
	}
}

func TestTrySendDatagramQueueFull(t *testing.T) {
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
	defer cancel()
	conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")

	// The calls go faster than the congestion window lets the packets out, so
	// the send queue (16384 frames) fills.
	payload := make([]byte, 1000)
	done := make(chan int, 1)
	go func() {
		var full int
		for range 3 * 16384 {
			err := conn.TrySendDatagram(payload)
			if errors.Is(err, quic.ErrDatagramQueueFull) {
				full++
				continue
			}
			if err != nil {
				t.Errorf("TrySendDatagram: %v", err)
				break
			}
		}
		done <- full
	}()
	select {
	case full := <-done:
		require.NotZero(t, full, "no call found the send queue full")
	case <-time.After(scaleDuration(5 * time.Second)):
		t.Fatal("TrySendDatagram waited")
	}
}
