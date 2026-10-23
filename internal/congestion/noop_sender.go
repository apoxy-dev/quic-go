package congestion

import (
	"math"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// NoopSender is a no-op congestion controller that always allows sending.
// Use this when an inner transport (e.g. netstack TCP) already handles
// congestion control and QUIC CC is redundant.
type NoopSender struct {
	maxDatagramSize protocol.ByteCount
	connStats       *utils.ConnectionStats
}

var _ SendAlgorithmWithDebugInfos = &NoopSender{}

func NewNoopSender(connStats *utils.ConnectionStats) *NoopSender {
	return &NoopSender{maxDatagramSize: initialMaxDatagramSize, connStats: connStats}
}

func (n *NoopSender) TimeUntilSend(protocol.ByteCount) monotime.Time { return 0 }
func (n *NoopSender) HasPacingBudget(monotime.Time) bool             { return true }
func (n *NoopSender) OnPacketSent(monotime.Time, protocol.ByteCount, protocol.PacketNumber, protocol.ByteCount, bool) {
}
func (n *NoopSender) CanSend(protocol.ByteCount) bool { return true }
func (n *NoopSender) MaybeExitSlowStart()             {}
func (n *NoopSender) OnPacketAcked(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount, monotime.Time) {
}

// OnCongestionEvent counts the loss as the Cubic sender does, so that the
// ConnectionStats loss counters work with congestion control off.
func (n *NoopSender) OnCongestionEvent(_ protocol.PacketNumber, lostBytes, _ protocol.ByteCount) {
	n.connStats.PacketsLost.Add(1)
	n.connStats.BytesLost.Add(uint64(lostBytes))
}
func (n *NoopSender) OnRetransmissionTimeout(bool)            {}
func (n *NoopSender) SetMaxDatagramSize(s protocol.ByteCount) { n.maxDatagramSize = s }
func (n *NoopSender) InSlowStart() bool                       { return false }
func (n *NoopSender) InRecovery() bool                        { return false }
func (n *NoopSender) GetCongestionWindow() protocol.ByteCount {
	return protocol.ByteCount(math.MaxInt64)
}
