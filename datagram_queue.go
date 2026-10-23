package quic

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	maxDatagramSendQueueLen = 16384
	maxDatagramRcvQueueLen  = 16384

	// smallDatagramSize is the buffer size for small received datagrams.
	smallDatagramSize = 256
)

// The pools keep buffers for received datagrams, one pool for each buffer size.
var smallDatagramPool, datagramPool sync.Pool

func init() {
	smallDatagramPool.New = func() any { return new([smallDatagramSize]byte) }
	datagramPool.New = func() any { return new([protocol.MaxPacketBufferSize]byte) }
}

// getDatagramBuffer returns a buffer of length n from a pool.
func getDatagramBuffer(n int) []byte {
	switch {
	case n <= smallDatagramSize:
		return smallDatagramPool.Get().(*[smallDatagramSize]byte)[:n]
	case n <= protocol.MaxPacketBufferSize:
		return datagramPool.Get().(*[protocol.MaxPacketBufferSize]byte)[:n]
	default:
		return make([]byte, n)
	}
}

// ReleaseDatagram gives a datagram from ReceiveDatagram or ReceiveDatagrams back for reuse.
// The caller must not use b or slices of b after the call.
// A datagram that is not released is garbage collected.
func ReleaseDatagram(b []byte) {
	switch cap(b) {
	case smallDatagramSize:
		smallDatagramPool.Put((*[smallDatagramSize]byte)(b[:smallDatagramSize]))
	case protocol.MaxPacketBufferSize:
		datagramPool.Put((*[protocol.MaxPacketBufferSize]byte)(b[:protocol.MaxPacketBufferSize]))
	}
}

// releaseDatagramFrame gives the data of a DATAGRAM frame that is sent or dropped back to the pool.
func releaseDatagramFrame(f *wire.DatagramFrame) {
	ReleaseDatagram(f.Data)
	f.Data = nil
}

// releaseSentDatagrams releases the DATAGRAM frames of a sent packet.
func releaseSentDatagrams(frames []ackhandler.Frame) {
	for _, f := range frames {
		if df, ok := f.Frame.(*wire.DatagramFrame); ok {
			releaseDatagramFrame(df)
		}
	}
}

type datagramQueue struct {
	sendMx    sync.RWMutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // Add waits on it when the send queue is full.

	rcvMx    sync.Mutex
	rcvQueue ringbuffer.RingBuffer[[]byte]
	rcvd     chan struct{} // receive waits on it when no datagram is ready.
	// ready is the number of datagrams at the front of rcvQueue that receive can take: the
	// datagrams of the passes of the run loop that ended.
	ready int
	// pending is set when HandleDatagramFrame queued a datagram after the last wake. Only the
	// run loop uses it.
	pending  bool
	rcvDrops atomic.Uint64

	closeErr error
	closed   chan struct{}

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
}

// Add queues a DATAGRAM frame to send.
// When the send queue is full, Add blocks until the packer takes a frame.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	for !h.push(f) {
		select {
		case <-h.closed:
			return h.closeErr
		case <-h.sent:
		}
	}
	return nil
}

// TryAdd queues a DATAGRAM frame to send.
// When the send queue is full, TryAdd returns ErrDatagramQueueFull at once.
func (h *datagramQueue) TryAdd(f *wire.DatagramFrame) error {
	if h.push(f) {
		return nil
	}
	select {
	case <-h.closed:
		return h.closeErr
	default:
		return ErrDatagramQueueFull
	}
}

// push queues f if the send queue is not full.
func (h *datagramQueue) push(f *wire.DatagramFrame) bool {
	h.sendMx.Lock()
	if h.sendQueue.Len() >= maxDatagramSendQueueLen {
		h.sendMx.Unlock()
		return false
	}
	h.sendQueue.PushBack(f)
	h.sendMx.Unlock()
	h.hasData()
	return true
}

// Peek returns the next DATAGRAM frame to send, or nil.
// After the packer sends the frame, it must call Pop before the next Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.RLock()
	defer h.sendMx.RUnlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

// Pop removes the frame that Peek returned.
func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	_ = h.sendQueue.PopFront()
	h.sendMx.Unlock()
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame queues a copy of the frame data, or drops and counts it when the queue is full.
// It does not wake a receiver: the run loop calls wake after the packets of one wakeup.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := getDatagramBuffer(len(f.Data))
	copy(data, f.Data)
	h.rcvMx.Lock()
	if h.rcvQueue.Len() >= maxDatagramRcvQueueLen {
		h.rcvMx.Unlock()
		ReleaseDatagram(data)
		h.rcvDrops.Add(1)
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
		return
	}
	h.rcvQueue.PushBack(data)
	h.rcvMx.Unlock()
	h.pending = true
}

// wake makes the datagrams queued after the last wake ready, and wakes a receiver. Only the run
// loop calls it, after the packets of one wakeup.
func (h *datagramQueue) wake() {
	if !h.pending {
		return
	}
	h.pending = false
	h.rcvMx.Lock()
	h.ready = h.rcvQueue.Len()
	h.rcvMx.Unlock()
	select {
	case h.rcvd <- struct{}{}:
	default:
	}
}

// receive waits for ready datagrams and puts up to len(bufs) of them in bufs, oldest first. After
// the close, all queued datagrams are ready, then the close error comes. No buffers return 0.
func (h *datagramQueue) receive(ctx context.Context, bufs [][]byte) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	closed := false
	for {
		h.rcvMx.Lock()
		if closed {
			// The run loop stopped, so no pass is open.
			h.ready = h.rcvQueue.Len()
		}
		n := min(len(bufs), h.ready)
		for i := range n {
			bufs[i] = h.rcvQueue.PopFront()
		}
		h.ready -= n
		h.rcvMx.Unlock()
		if n > 0 {
			return n, nil
		}
		if closed {
			return 0, h.closeErr
		}
		select {
		case <-h.rcvd:
		case <-h.closed:
			closed = true
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
}
