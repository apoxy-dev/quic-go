package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatagramNegotiation(t *testing.T) {
	t.Run("server enable, client enable", func(t *testing.T) {
		testDatagramNegotiation(t, true, true)
	})
	t.Run("server enable, client disable", func(t *testing.T) {
		testDatagramNegotiation(t, true, false)
	})
	t.Run("server disable, client enable", func(t *testing.T) {
		testDatagramNegotiation(t, false, true)
	})
	t.Run("server disable, client disable", func(t *testing.T) {
		testDatagramNegotiation(t, false, false)
	})
}

func testDatagramNegotiation(t *testing.T, serverEnableDatagram, clientEnableDatagram bool) {
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: serverEnableDatagram}),
	)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: clientEnableDatagram}),
	)
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	if clientEnableDatagram {
		require.True(t, serverConn.ConnectionState().SupportsDatagrams)
		require.NoError(t, serverConn.SendDatagram([]byte("foo")))
		datagram, err := clientConn.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte("foo"), datagram)
	} else {
		require.False(t, serverConn.ConnectionState().SupportsDatagrams)
		require.Error(t, serverConn.SendDatagram([]byte("foo")))
	}

	if serverEnableDatagram {
		require.True(t, clientConn.ConnectionState().SupportsDatagrams)
		require.NoError(t, clientConn.SendDatagram([]byte("bar")))
		datagram, err := serverConn.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, []byte("bar"), datagram)
	} else {
		require.False(t, clientConn.ConnectionState().SupportsDatagrams)
		require.Error(t, clientConn.SendDatagram([]byte("bar")))
	}
}

func TestDatagramSizeLimit(t *testing.T) {
	const maxDatagramSize = 456
	originalMaxDatagramSize := wire.MaxDatagramSize
	wire.MaxDatagramSize = maxDatagramSize
	t.Cleanup(func() { wire.MaxDatagramSize = originalMaxDatagramSize })

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	err = clientConn.SendDatagram(bytes.Repeat([]byte("a"), maxDatagramSize+100)) // definitely too large
	require.Error(t, err)
	var sizeErr *quic.DatagramTooLargeError
	require.ErrorAs(t, err, &sizeErr)
	require.InDelta(t, sizeErr.MaxDatagramPayloadSize, maxDatagramSize, 10)

	require.NoError(t, clientConn.SendDatagram(bytes.Repeat([]byte("b"), int(sizeErr.MaxDatagramPayloadSize))))
	require.Error(t, clientConn.SendDatagram(bytes.Repeat([]byte("c"), int(sizeErr.MaxDatagramPayloadSize+1))))

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")
	datagram, err := serverConn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte("b"), int(sizeErr.MaxDatagramPayloadSize)), datagram)
}

func TestDatagramSizeLimitWithMTUDiscovery(t *testing.T) {
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	type mtuUpdate struct {
		mtu  logging.ByteCount
		done bool
	}
	var mx sync.Mutex
	var updates []mtuUpdate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			InitialPacketSize: protocol.MinInitialPacketSize,
			EnableDatagrams:   true,
			Tracer: newTracer(&logging.ConnectionTracer{
				UpdatedMTU: func(mtu logging.ByteCount, done bool) {
					mx.Lock()
					defer mx.Unlock()
					updates = append(updates, mtuUpdate{mtu: mtu, done: done})
				},
			}),
		}),
	)
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	serverErrChan := make(chan error, 1)
	go func() {
		str, err := serverConn.AcceptStream(ctx)
		if err != nil {
			serverErrChan <- err
			return
		}
		_, err = io.Copy(io.Discard, str)
		serverErrChan <- err
	}()

	str, err := clientConn.OpenStream()
	require.NoError(t, err)

	data := bytes.Repeat([]byte("d"), 16*1024)
	var discoveredMTU logging.ByteCount
	var checkedMTUUpdates int
	var previousMaxPayloadSize int64
	for discoveredMTU == 0 {
		_, err = str.Write(data)
		require.NoError(t, err)
		mx.Lock()
		events := append([]mtuUpdate(nil), updates...)
		mx.Unlock()
		for ; checkedMTUUpdates < len(events); checkedMTUUpdates++ {
			update := events[checkedMTUUpdates]
			err = clientConn.SendDatagram(bytes.Repeat([]byte("x"), 2000))
			var sizeErr *quic.DatagramTooLargeError
			require.ErrorAs(t, err, &sizeErr)
			maxPayloadSize := sizeErr.MaxDatagramPayloadSize
			require.Greater(t, maxPayloadSize, int64(0))
			require.GreaterOrEqual(t, maxPayloadSize, previousMaxPayloadSize)
			require.Less(t, maxPayloadSize, int64(update.mtu))
			previousMaxPayloadSize = maxPayloadSize

			datagramData := bytes.Repeat([]byte("z"), int(maxPayloadSize))
			err = clientConn.SendDatagram(datagramData)
			require.NoError(t, err)

			datagram, err := serverConn.ReceiveDatagram(ctx)
			require.NoError(t, err, "datagram should be deliverable when respecting MaxDatagramPayloadSize")
			require.Equal(t, datagramData, datagram)

			if update.done {
				discoveredMTU = update.mtu
			}
		}
		require.NoError(t, ctx.Err())
	}
	require.NoError(t, str.Close())

	select {
	case err := <-serverErrChan:
		require.NoError(t, err)
	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	}
}

// Near the packet size, SendDatagram must refuse each datagram that the packer cannot send.
func TestDatagramSizeNearInitialPacketSize(t *testing.T) {
	tests := []struct {
		ips       uint16
		connIDLen int
	}{
		{ips: 1280, connIDLen: 4},
		{ips: 1321, connIDLen: 4},
		{ips: 1350, connIDLen: 4},
		{ips: 1350, connIDLen: 8},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("size %d, connection ID %d", test.ips, test.connIDLen), func(t *testing.T) {
			conf := getQuicConfig(&quic.Config{
				EnableDatagrams:         true,
				InitialPacketSize:       test.ips,
				DisablePathMTUDiscovery: true,
			})
			serverTr := &quic.Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: test.connIDLen}
			defer serverTr.Close()
			addTracer(serverTr)
			server, err := serverTr.Listen(getTLSConfig(), conf)
			require.NoError(t, err)
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			clientTr := &quic.Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: test.connIDLen}
			defer clientTr.Close()
			addTracer(clientTr)
			clientConn, err := clientTr.Dial(ctx, server.Addr(), getTLSClientConfig(), conf)
			require.NoError(t, err)
			defer clientConn.CloseWithError(0, "")
			serverConn, err := server.Accept(ctx)
			require.NoError(t, err)
			defer serverConn.CloseWithError(0, "")

			// After a stream round trip, both sides have handled ACK frames.
			go func() {
				str, err := serverConn.AcceptStream(ctx)
				if err != nil {
					return
				}
				io.Copy(str, str)
				str.Close()
			}()
			str, err := clientConn.OpenStreamSync(ctx)
			require.NoError(t, err)
			_, err = str.Write([]byte("ping"))
			require.NoError(t, err)
			require.NoError(t, str.Close())
			data, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, []byte("ping"), data)

			t.Run("client", func(t *testing.T) { testDatagramSizes(t, clientConn, serverConn, int(test.ips)) })
			t.Run("server", func(t *testing.T) { testDatagramSizes(t, serverConn, clientConn, int(test.ips)) })
		})
	}
}

// testDatagramSizes sends one datagram of each size from ips-40 to ips. Each datagram that SendDatagram accepts must arrive.
func testDatagramSizes(t *testing.T, sender, receiver quic.Connection, ips int) {
	var accepted int
	for size := ips - 40; size <= ips; size++ {
		data := bytes.Repeat([]byte{byte(size)}, size)
		if err := sender.SendDatagram(data); err != nil {
			var sizeErr *quic.DatagramTooLargeError
			require.ErrorAs(t, err, &sizeErr)
			continue
		}
		accepted++
		ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(time.Second))
		got, err := receiver.ReceiveDatagram(ctx)
		cancel()
		require.NoError(t, err, "a datagram of %d bytes was accepted, but it did not arrive", size)
		require.Equal(t, data, got)
	}
	require.NotZero(t, accepted)
}

// Datagrams of changing sizes go out in GSO batches. The sender must not drop any of them.
func TestDatagramGSOMixedSizes(t *testing.T) {
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	var sent atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			EnableDatagrams:          true,
			DisableCongestionControl: true,
			Tracer: newTracer(&logging.ConnectionTracer{
				SentShortHeaderPacket: func(_ *logging.ShortHeader, _ logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, frames []logging.Frame) {
					for _, f := range frames {
						if _, ok := f.(*logging.DatagramFrame); ok {
							sent.Add(1)
						}
					}
				},
			}),
		}),
	)
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")
	if !clientConn.ConnectionState().GSO {
		t.Skip("GSO is not available")
	}

	// A small datagram before a large one starts a batch with small segments.
	sizes := []int{100, 1100, 40, 1000, 1000, 300}
	const num = 6000
	for i := 0; i < num; i++ {
		require.NoError(t, clientConn.SendDatagram(make([]byte, sizes[i%len(sizes)])))
	}
	for start := time.Now(); sent.Load() < num && time.Since(start) < scaleDuration(time.Second); {
		time.Sleep(time.Millisecond)
	}
	require.Equal(t, int64(num), sent.Load())
}

func TestDatagramLoss(t *testing.T) {
	const rtt = 10 * time.Millisecond
	const numDatagrams = 100
	const datagramSize = 500

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	var droppedIncoming, droppedOutgoing, total atomic.Int32
	proxy := &quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: server.Addr().(*net.UDPAddr),
		// Drop about 10% of Short Header packets with DATAGRAM frames
		DropPacket: func(dir quicproxy.Direction, _, _ net.Addr, packet []byte) bool {
			if wire.IsLongHeaderPacket(packet[0]) { // don't drop Long Header packets
				return false
			}
			if len(packet) < datagramSize { // don't drop ACK-only packets
				return false
			}
			total.Add(1)
			if mrand.Int()%10 == 0 {
				switch dir {
				case quicproxy.DirectionIncoming:
					droppedIncoming.Add(1)
				case quicproxy.DirectionOutgoing:
					droppedOutgoing.Add(1)
				}
				return true
			}
			return false
		},
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return rtt / 2 },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	// SendDatagram blocks when the queue is full (maxDatagramSendQueueLen),
	// add some extra margin for the handshake, networking and ACKs.
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(4*numDatagrams*time.Millisecond))
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		proxy.LocalAddr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	var clientDatagrams, serverDatagrams int
	clientErrChan := make(chan error, 1)
	go func() {
		defer close(clientErrChan)
		for {
			if _, err := clientConn.ReceiveDatagram(ctx); err != nil {
				clientErrChan <- err
				return
			}
			clientDatagrams++
		}
	}()

	for i := 0; i < numDatagrams; i++ {
		payload := bytes.Repeat([]byte{uint8(i)}, datagramSize)
		require.NoError(t, clientConn.SendDatagram(payload))
		require.NoError(t, serverConn.SendDatagram(payload))
		time.Sleep(scaleDuration(time.Millisecond / 2))
	}

	serverErrChan := make(chan error, 1)
	go func() {
		defer close(serverErrChan)
		for {
			if _, err := serverConn.ReceiveDatagram(ctx); err != nil {
				serverErrChan <- err
				return
			}
			serverDatagrams++
		}
	}()

	select {
	case err := <-clientErrChan:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(scaleDuration(5 * numDatagrams * time.Millisecond)):
		t.Fatal("timeout")
	}
	select {
	case err := <-serverErrChan:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(scaleDuration(5 * numDatagrams * time.Millisecond)):
		t.Fatal("timeout")
	}

	numDroppedIncoming := droppedIncoming.Load()
	numDroppedOutgoing := droppedOutgoing.Load()
	t.Logf("dropped %d incoming and %d outgoing out of %d packets", numDroppedIncoming, numDroppedOutgoing, total.Load())
	assert.NotZero(t, numDroppedIncoming)
	assert.NotZero(t, numDroppedOutgoing)
	t.Logf("server received %d out of %d sent datagrams", serverDatagrams, numDatagrams)
	assert.EqualValues(t, numDatagrams-numDroppedIncoming, serverDatagrams, "datagrams received by the server")
	t.Logf("client received %d out of %d sent datagrams", clientDatagrams, numDatagrams)
	assert.EqualValues(t, numDatagrams-numDroppedOutgoing, clientDatagrams, "datagrams received by the client")
}
