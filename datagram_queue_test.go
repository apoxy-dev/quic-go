package quic

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/integrationtests/tools/israce"
	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatagramQueuePeekAndPop(t *testing.T) {
	var queued []struct{}
	queue := newDatagramQueue(func() { queued = append(queued, struct{}{}) }, utils.DefaultLogger)
	require.Nil(t, queue.Peek())
	require.Empty(t, queued)
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}))
	require.Len(t, queued, 1)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	// calling peek again returns the same datagram
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	queue.Pop()
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueSendQueueLength(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}
	errChan := make(chan error, 1)
	go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()

	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// peeking doesn't remove the datagram from the queue...
	require.NotNil(t, queue.Peek())
	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// ...but popping does
	queue.Pop()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	// pop all the remaining datagrams
	for i := 1; i < maxDatagramSendQueueLen; i++ {
		queue.Pop()
	}
	f := queue.Peek()
	require.NotNil(t, f)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, f)
}

func TestDatagramQueueReceive(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	// receive frames that were received earlier
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), data)
	data, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)
}

func TestDatagramQueueReceiveBlocking(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	// block until a new frame is received
	type result struct {
		data []byte
		err  error
	}
	resultChan := make(chan result, 1)
	go func() {
		data, err := queue.Receive(context.Background())
		resultChan <- result{data, err}
	}()

	select {
	case <-resultChan:
		t.Fatal("expected to not receive result")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	select {
	case result := <-resultChan:
		require.NoError(t, result.err)
		require.Equal(t, []byte("foobar"), result.data)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// unblock when the context is canceled
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() {
		_, err := queue.Receive(ctx)
		errChan <- err
	}()
	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestDatagramQueueClose(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}
	errChan1 := make(chan error, 1)
	go func() { errChan1 <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()
	errChan2 := make(chan error, 1)
	go func() {
		_, err := queue.Receive(context.Background())
		errChan2 <- err
	}()

	queue.CloseWithError(assert.AnError)

	select {
	case err := <-errChan1:
		require.ErrorIs(t, err, assert.AnError)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	select {
	case err := <-errChan2:
		require.ErrorIs(t, err, assert.AnError)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestDatagramQueueReceiveQueueFull(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	for i := 0; i < maxDatagramRcvQueueLen; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("dropped")})
	require.Equal(t, uint64(1), queue.rcvDrops.Load())

	// The queue accepts a datagram again after Receive takes one.
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte{0}, data)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	require.Equal(t, uint64(1), queue.rcvDrops.Load())
}

func TestDatagramBuffers(t *testing.T) {
	tests := []struct {
		size    int
		wantCap int
		pooled  bool
	}{
		{size: 0, wantCap: smallDatagramSize, pooled: true},
		{size: smallDatagramSize, wantCap: smallDatagramSize, pooled: true},
		{size: smallDatagramSize + 1, wantCap: protocol.MaxPacketBufferSize, pooled: true},
		{size: protocol.MaxPacketBufferSize, wantCap: protocol.MaxPacketBufferSize, pooled: true},
		{size: protocol.MaxPacketBufferSize + 1, wantCap: protocol.MaxPacketBufferSize + 1},
	}
	for _, test := range tests {
		t.Run(strconv.Itoa(test.size), func(t *testing.T) {
			queue := newDatagramQueue(func() {}, utils.DefaultLogger)
			data := bytes.Repeat([]byte{'a'}, test.size)
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data})
			got, err := queue.Receive(context.Background())
			require.NoError(t, err)
			require.Equal(t, data, got)
			require.Equal(t, test.wantCap, cap(got))
			// The queue keeps a copy, not the frame data.
			if test.size > 0 {
				data[0] = 'b'
				require.NotEqual(t, data, got)
			}
			ReleaseDatagram(got)

			if israce.Enabled {
				t.Skip("sync.Pool drops buffers when the race detector is on")
			}
			allocs := testing.AllocsPerRun(100, func() {
				queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data})
				b, _ := queue.Receive(context.Background())
				ReleaseDatagram(b)
			})
			if test.pooled {
				require.Zero(t, allocs)
			} else {
				require.Equal(t, float64(1), allocs)
			}
		})
	}
}

func BenchmarkDatagramQueueReceive(b *testing.B) {
	for _, release := range []bool{false, true} {
		name := "keep"
		if release {
			name = "release"
		}
		b.Run(name, func(b *testing.B) {
			queue := newDatagramQueue(func() {}, utils.DefaultLogger)
			f := &wire.DatagramFrame{Data: make([]byte, 1350)}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				queue.HandleDatagramFrame(f)
				data, err := queue.Receive(context.Background())
				if err != nil {
					b.Fatal(err)
				}
				if release {
					ReleaseDatagram(data)
				}
			}
		})
	}
}

func TestReleaseSentDatagrams(t *testing.T) {
	df := &wire.DatagramFrame{Data: getDatagramBuffer(100)}
	ping := &wire.PingFrame{}
	frames := []ackhandler.Frame{{Frame: ping}, {Frame: df}, {}}
	releaseSentDatagrams(frames)
	require.Nil(t, df.Data)
	require.Equal(t, ping, frames[0].Frame)
	require.Nil(t, frames[2].Frame)
}
