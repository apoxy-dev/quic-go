package quic

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/synctest"
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
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)

		for range maxDatagramSendQueueLen {
			require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
		}
		errChan := make(chan error, 1)
		go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()

		synctest.Wait()

		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		// peeking doesn't remove the datagram from the queue...
		require.NotNil(t, queue.Peek())
		synctest.Wait()
		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		// ...but popping does
		queue.Pop()
		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
		// pop all the remaining datagrams
		for range maxDatagramSendQueueLen - 1 {
			queue.Pop()
		}
		f := queue.Peek()
		require.NotNil(t, f)
		require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, f)
	})
}

func TestDatagramQueueTryAdd(t *testing.T) {
	cases := []struct {
		name    string
		queued  int
		closed  bool
		wantErr error
	}{
		{name: "space in the queue", queued: maxDatagramSendQueueLen - 1},
		{name: "full queue", queued: maxDatagramSendQueueLen, wantErr: ErrDatagramQueueFull},
		{name: "full queue, closed", queued: maxDatagramSendQueueLen, closed: true, wantErr: assert.AnError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			queue := newDatagramQueue(func() {}, utils.DefaultLogger)
			for i := 0; i < tc.queued; i++ {
				require.NoError(t, queue.TryAdd(&wire.DatagramFrame{Data: []byte{0}}))
			}
			if tc.closed {
				queue.CloseWithError(assert.AnError)
			}
			errChan := make(chan error, 1)
			go func() { errChan <- queue.TryAdd(&wire.DatagramFrame{Data: []byte("foobar")}) }()
			select {
			case err := <-errChan:
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("TryAdd waited")
			}
			for i := 0; i < tc.queued; i++ {
				queue.Pop()
			}
			require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, queue.Peek())
		})
	}
}

// queueStep is one step of TestDatagramQueueReceive, in field order. A step with recv calls
// receive with bufs buffers, or takes the result of the receive that waits.
type queueStep struct {
	push   int  // Queue this many datagrams, as the run loop does in a pass.
	wake   bool // End the pass.
	close  bool // Close the queue with assert.AnError.
	cancel bool // Cancel the context of receive.
	recv   bool
	bufs   int
	want   int   // The number of datagrams that receive returns.
	err    error // The error that receive returns.
	waits  bool  // receive still waits after the step.
}

// then makes s also take the result of the receive that waits, which returns n datagrams.
func (s queueStep) then(n int) queueStep {
	s.recv, s.want = true, n
	return s
}

func TestDatagramQueueReceive(t *testing.T) {
	push := func(n int) queueStep { return queueStep{push: n} }
	recv := func(bufs, want int) queueStep { return queueStep{recv: true, bufs: bufs, want: want} }
	recvErr := func(err error) queueStep { return queueStep{recv: true, bufs: 4, err: err} }
	recvWaits := func(bufs int) queueStep { return queueStep{recv: true, bufs: bufs, waits: true} }
	wake := queueStep{wake: true}
	closeQueue := queueStep{close: true}
	cases := []struct {
		name  string
		steps []queueStep
	}{
		{"part of a pass", []queueStep{push(3), wake, recv(2, 2), recv(2, 1)}},
		{"a pass larger than the buffers", []queueStep{push(100), wake, recv(64, 64), recv(64, 36)}},
		{"several passes in one call", []queueStep{push(2), wake, push(3), wake, recv(8, 5)}},
		{"no buffers", []queueStep{push(1), wake, recv(0, 0), recv(1, 1)}},
		{"a pass that did not end", []queueStep{push(1), recvWaits(4), wake.then(1)}},
		{"a pass in progress after an ended pass", []queueStep{push(2), wake, push(1), recv(4, 2), recvWaits(4), wake.then(1)}},
		{"a receiver that waits before the pass", []queueStep{recvWaits(4), {push: 3, recv: true, waits: true}, wake.then(3)}},
		{"close with a pass in progress", []queueStep{push(2), closeQueue, recv(4, 2), recvErr(assert.AnError)}},
		{"close after a receive", []queueStep{push(2), wake, recv(1, 1), closeQueue, recv(4, 1), recvErr(assert.AnError)}},
		{"close while a receiver waits", []queueStep{push(1), recvWaits(4), closeQueue.then(1), recvErr(assert.AnError)}},
		{"context canceled", []queueStep{recvWaits(1), {cancel: true, recv: true, err: context.Canceled}}},
		{"context canceled with a ready datagram", []queueStep{push(1), wake, {cancel: true}, recv(1, 1), recvErr(context.Canceled)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				queue := newDatagramQueue(func() {}, utils.DefaultLogger)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				type result struct {
					n   int
					err error
				}
				unused := []byte("unused")
				var pushed, received int
				var bufs [][]byte
				var res chan result // The result of the receive that runs.
				for i, s := range tc.steps {
					for range s.push {
						queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(pushed)}})
						pushed++
					}
					if s.wake {
						queue.wake()
					}
					if s.close {
						queue.CloseWithError(assert.AnError)
					}
					if s.cancel {
						cancel()
					}
					if !s.recv {
						continue
					}
					if res == nil {
						bufs = make([][]byte, s.bufs)
						for j := range bufs {
							bufs[j] = unused
						}
						res = make(chan result, 1)
						go func() {
							n, err := queue.receive(ctx, bufs)
							res <- result{n, err}
						}()
					}
					synctest.Wait()
					if s.waits {
						require.Empty(t, res, "step %d: receive returned", i)
						continue
					}
					var r result
					select {
					case r = <-res:
						res = nil
					default:
						t.Fatalf("step %d: receive waits", i)
					}
					if s.err != nil {
						require.ErrorIs(t, r.err, s.err, "step %d", i)
						require.Zero(t, r.n, "step %d", i)
					} else {
						require.NoError(t, r.err, "step %d", i)
						require.Equal(t, s.want, r.n, "step %d", i)
					}
					// The datagrams come back in the order of the pushes, and the other buffers do not change.
					for _, b := range bufs[:r.n] {
						require.Equal(t, []byte{byte(received)}, b, "step %d", i)
						received++
					}
					for _, b := range bufs[r.n:] {
						require.Equal(t, unused, b, "step %d", i)
					}
				}
				require.Nil(t, res, "a receive still waits")
			})
		})
	}
}

// receiveOne ends the pass and receives one datagram.
func receiveOne(q *datagramQueue) ([]byte, error) {
	q.wake()
	var bufs [1][]byte
	if _, err := q.receive(context.Background(), bufs[:]); err != nil {
		return nil, err
	}
	return bufs[0], nil
}

func TestDatagramQueueClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)

		for range maxDatagramSendQueueLen {
			require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
		}
		errChan1 := make(chan error, 1)
		go func() { errChan1 <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()
		errChan2 := make(chan error, 1)
		go func() {
			_, err := receiveOne(queue)
			errChan2 <- err
		}()

		queue.CloseWithError(assert.AnError)
		synctest.Wait()

		select {
		case err := <-errChan1:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("should have received an error")
		}

		select {
		case err := <-errChan2:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("should have received an error")
		}
	})
}

func TestDatagramQueueReceiveQueueFull(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	for i := 0; i < maxDatagramRcvQueueLen; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("dropped")})
	require.Equal(t, uint64(1), queue.rcvDrops.Load())

	// The queue accepts a datagram again after receive takes one.
	data, err := receiveOne(queue)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, data)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	require.Equal(t, uint64(1), queue.rcvDrops.Load())

	// The wake makes all queued datagrams ready, and the dropped one is not among them.
	queue.wake()
	bufs := make([][]byte, maxDatagramRcvQueueLen+1)
	n, err := queue.receive(context.Background(), bufs)
	require.NoError(t, err)
	require.Equal(t, maxDatagramRcvQueueLen, n)
	require.Equal(t, []byte{1}, bufs[0])
	require.Equal(t, []byte("foobar"), bufs[n-1])
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
			got, err := receiveOne(queue)
			require.NoError(t, err)
			require.Equal(t, data, got)
			require.Equal(t, test.wantCap, cap(got))
			// The queue keeps a copy, not the frame data.
			if test.size > 0 {
				data[0] = 'b'
				require.NotEqual(t, data, got)
			}
			ReleaseDatagram(got)

			if raceEnabled {
				t.Skip("sync.Pool drops buffers when the race detector is on")
			}
			allocs := testing.AllocsPerRun(100, func() {
				queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data})
				b, _ := receiveOne(queue)
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
				data, err := receiveOne(queue)
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
