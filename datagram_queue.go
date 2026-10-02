package quic

import (
	"context"
	"sync"
	"sync/atomic"

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

// ReleaseDatagram gives a datagram from ReceiveDatagram back for reuse.
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

type datagramQueue struct {
	sendMx    sync.RWMutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // Add waits on it when the send queue is full.

	rcvMx    sync.Mutex
	rcvQueue ringbuffer.RingBuffer[[]byte]
	rcvd     chan struct{} // Receive waits on it when the receive queue is empty.
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
	for {
		h.sendMx.Lock()
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		h.sendMx.Unlock()
		select {
		case <-h.closed:
			return h.closeErr
		case <-h.sent:
		}
	}
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

// HandleDatagramFrame queues a copy of the frame data for Receive.
// The frame data can be part of the packet buffer.
// When the receive queue is full, it drops the datagram.
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
	select {
	case h.rcvd <- struct{}{}:
	default:
	}
}

// Receive returns the next received datagram.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if !h.rcvQueue.Empty() {
			data := h.rcvQueue.PopFront()
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
}
