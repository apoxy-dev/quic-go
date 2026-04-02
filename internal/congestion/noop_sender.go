package congestion

import (
	"math"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

// NoopSender is a no-op congestion controller that always allows sending.
// Use this when an inner transport (e.g. netstack TCP) already handles
// congestion control and QUIC CC is redundant.
type NoopSender struct {
	maxDatagramSize protocol.ByteCount
}

var _ SendAlgorithmWithDebugInfos = &NoopSender{}

func NewNoopSender() *NoopSender {
	return &NoopSender{maxDatagramSize: initialMaxDatagramSize}
}

func (n *NoopSender) TimeUntilSend(protocol.ByteCount) time.Time { return time.Time{} }
func (n *NoopSender) HasPacingBudget(time.Time) bool             { return true }
func (n *NoopSender) OnPacketSent(time.Time, protocol.ByteCount, protocol.PacketNumber, protocol.ByteCount, bool) {
}
func (n *NoopSender) CanSend(protocol.ByteCount) bool     { return true }
func (n *NoopSender) MaybeExitSlowStart()                  {}
func (n *NoopSender) OnPacketAcked(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount, time.Time) {
}
func (n *NoopSender) OnCongestionEvent(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount) {
}
func (n *NoopSender) OnRetransmissionTimeout(bool)                {}
func (n *NoopSender) SetMaxDatagramSize(s protocol.ByteCount)     { n.maxDatagramSize = s }
func (n *NoopSender) InSlowStart() bool                           { return false }
func (n *NoopSender) InRecovery() bool                            { return false }
func (n *NoopSender) GetCongestionWindow() protocol.ByteCount     { return protocol.ByteCount(math.MaxInt64) }
