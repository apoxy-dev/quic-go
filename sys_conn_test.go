package quic

import (
	"bytes"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestBasicConn(t *testing.T) {
	mockCtrl := gomock.NewController(t)

	c := NewMockPacketConn(mockCtrl)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
	c.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func(b []byte) (int, net.Addr, error) {
		data := []byte("foobar")
		require.Equal(t, protocol.MaxPacketBufferSize, len(b))
		return copy(b, data), addr, nil
	})

	conn, err := wrapConn(c, false)
	require.NoError(t, err)
	p, err := conn.ReadPacket()
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), p.data)
	require.WithinDuration(t, time.Now(), p.rcvTime.ToTime(), scaleDuration(100*time.Millisecond))
	require.Equal(t, addr, p.remoteAddr)
}

// ecnWrite is one write of a recordingECNConn. gsoSize is 0 for a WriteToECN call.
type ecnWrite struct {
	b       []byte
	gsoSize uint16
	ecn     uint8
}

// recordingECNConn is an ECNPacketConn that records its writes.
type recordingECNConn struct {
	net.PacketConn // Only the methods below run.
	writes         []ecnWrite
	gsoErr         error // The error of each WriteToGSO call.
}

func (c *recordingECNConn) ReadFromECN([]byte) (int, net.Addr, uint8, error) {
	return 0, nil, 0, net.ErrClosed
}

func (c *recordingECNConn) WriteToECN(b []byte, _ net.Addr, ecn uint8) (int, error) {
	c.writes = append(c.writes, ecnWrite{b: bytes.Clone(b), ecn: ecn})
	return len(b), nil
}

func (c *recordingECNConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}
}

// recordingGSOConn is a recordingECNConn that also takes GSO batches.
type recordingGSOConn struct{ *recordingECNConn }

func (c recordingGSOConn) WriteToGSO(b []byte, _ net.Addr, gsoSize uint16, ecn uint8) (int, error) {
	if c.gsoErr != nil {
		return 0, c.gsoErr
	}
	c.writes = append(c.writes, ecnWrite{b: bytes.Clone(b), gsoSize: gsoSize, ecn: ecn})
	return len(b), nil
}

// TestECNConnGSO checks that a GSOPacketConn gets each GSO batch in one call with the ECN bits of
// the batch, and that an ECNPacketConn without it gets single writes.
func TestECNConnGSO(t *testing.T) {
	batch := bytes.Repeat([]byte{1}, 3*100+40) // Three packets of 100 bytes and one of 40.
	type send struct {
		gsoSize uint16
		ecn     protocol.ECN
	}
	cases := []struct {
		name    string
		gso     bool
		gsoErr  error
		sends   []send
		wantGSO bool // GSO after the sends.
		want    []ecnWrite
	}{
		{
			name:    "a GSO batch is one write",
			gso:     true,
			sends:   []send{{gsoSize: 100, ecn: protocol.ECT0}},
			wantGSO: true,
			want:    []ecnWrite{{b: batch, gsoSize: 100, ecn: 0b10}},
		},
		{
			name:    "each GSO batch has the ECN bits of its packets",
			gso:     true,
			sends:   []send{{gsoSize: 100, ecn: protocol.ECT0}, {gsoSize: 100, ecn: protocol.ECNCE}, {gsoSize: 100, ecn: protocol.ECNNon}},
			wantGSO: true,
			want:    []ecnWrite{{b: batch, gsoSize: 100, ecn: 0b10}, {b: batch, gsoSize: 100, ecn: 0b11}, {b: batch, gsoSize: 100, ecn: 0b00}},
		},
		{
			name:    "a packet without GSO is a single write",
			gso:     true,
			sends:   []send{{ecn: protocol.ECT1}},
			wantGSO: true,
			want:    []ecnWrite{{b: batch, ecn: 0b01}},
		},
		{
			// As with a UDP socket on an interface that cannot segment, quic-go sends the packets of
			// the batch one by one and stops GSO.
			name:   "a GSO error sends the packets one by one",
			gso:    true,
			gsoErr: &os.SyscallError{Syscall: "sendmsg", Err: syscall.EIO},
			sends:  []send{{gsoSize: 100, ecn: protocol.ECT0}},
			want: []ecnWrite{
				{b: batch[:100], ecn: 0b10}, {b: batch[100:200], ecn: 0b10}, {b: batch[200:300], ecn: 0b10}, {b: batch[300:], ecn: 0b10},
			},
		},
		{
			name:  "a conn without GSO gets single writes",
			sends: []send{{ecn: protocol.ECT0}, {ecn: protocol.ECNNon}},
			want:  []ecnWrite{{b: batch, ecn: 0b10}, {b: batch, ecn: 0b00}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.gsoErr != nil && !platformSupportsGSO {
				t.Skip("the GSO error is a Linux error")
			}
			rec := &recordingECNConn{gsoErr: tc.gsoErr}
			var pc net.PacketConn = rec
			if tc.gso {
				pc = recordingGSOConn{rec}
			}
			raw, err := wrapConn(pc, false)
			require.NoError(t, err)
			remote := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4433}
			c := newSendConn(raw, remote, packetInfo{}, utils.DefaultLogger)
			require.Equal(t, tc.gso, c.capabilities().GSO)
			require.True(t, c.capabilities().ECN)
			for _, s := range tc.sends {
				require.NoError(t, c.Write(batch, s.gsoSize, s.ecn))
			}
			require.Equal(t, tc.want, rec.writes)
			require.Equal(t, tc.wantGSO, c.capabilities().GSO)
		})
	}
}
