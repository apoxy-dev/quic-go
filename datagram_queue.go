package quic

import (
	"context"
	"sync"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	maxDatagramSendQueueLen = 16384
	maxDatagramRcvQueueLen  = 16384
)

type datagramQueue struct {
	sendMu sync.Mutex
	rcvMu  sync.Mutex

	// Send queue
	sendQueue []*wire.DatagramFrame
	sendCond  *sync.Cond

	// Receive queue
	rcvQueue []*wire.DatagramFrame
	rcvCond  *sync.Cond

	closeErr error
	closed   bool

	hasData func()
	logger  utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	q := &datagramQueue{
		hasData: hasData,
		logger:  logger,
	}
	q.sendCond = sync.NewCond(&q.sendMu)
	q.rcvCond = sync.NewCond(&q.rcvMu)
	return q
}

// Add queues a new DATAGRAM frame for sending.
// Blocks until there's space in the queue.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()

	for len(h.sendQueue) >= maxDatagramSendQueueLen && !h.closed {
		h.sendCond.Wait()
	}

	if h.closed {
		return h.closeErr
	}

	h.sendQueue = append(h.sendQueue, f)
	h.hasData()
	return nil
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()

	if len(h.sendQueue) == 0 {
		return nil
	}

	return h.sendQueue[0]
}

func (h *datagramQueue) Pop() {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()

	if len(h.sendQueue) > 0 {
		h.sendQueue = h.sendQueue[1:]
		h.sendCond.Signal()
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	h.rcvMu.Lock()
	defer h.rcvMu.Unlock()

	if len(h.rcvQueue) >= maxDatagramRcvQueueLen {
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
		return
	}

	h.rcvQueue = append(h.rcvQueue, f)
	h.rcvCond.Signal()
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	h.rcvMu.Lock()
	defer h.rcvMu.Unlock()

	// Check for immediate return conditions
	for {
		if h.closed {
			return nil, h.closeErr
		}

		if len(h.rcvQueue) > 0 {
			frame := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			return frame.Data, nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Need to wait - use goroutine to handle context cancellation
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				h.rcvMu.Lock()
				h.rcvCond.Broadcast()
				h.rcvMu.Unlock()
			case <-done:
			}
		}()

		h.rcvCond.Wait()
		close(done)
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.sendMu.Lock()
	h.rcvMu.Lock()
	defer h.sendMu.Unlock()
	defer h.rcvMu.Unlock()

	if h.closed {
		return
	}

	h.closeErr = e
	h.closed = true
	h.sendCond.Broadcast()
	h.rcvCond.Broadcast()
}
