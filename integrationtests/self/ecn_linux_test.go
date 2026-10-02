//go:build linux

package self_test

import (
	"context"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

// countECN counts the ECN codepoints of the 1-RTT packets that a connection received.
// The quic-go socket reads the TOS byte of each packet with IP_RECVTOS.
func countECN(r *events.Recorder) map[qlog.ECN]int {
	counts := make(map[qlog.ECN]int)
	for _, ev := range r.Events(qlog.PacketReceived{}) {
		if p := ev.(qlog.PacketReceived); p.Header.PacketType == qlog.PacketType1RTT {
			counts[p.ECN]++
		}
	}
	return counts
}

func TestDisableECN(t *testing.T) {
	if off, _ := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_ECN")); off {
		t.Skip("QUIC_GO_DISABLE_ECN turns ECN off for all connections")
	}
	cases := []struct {
		name                 string
		clientOff, serverOff bool
	}{
		{"ECN on", false, false},
		{"client off", true, false},
		{"server off", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fromClient, fromServer events.Recorder
			ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(),
				getQuicConfig(&quic.Config{DisableECN: tc.serverOff, Tracer: newTracer(&fromClient)}))
			require.NoError(t, err)
			defer ln.Close()

			ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
			defer cancel()
			conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(),
				getQuicConfig(&quic.Config{DisableECN: tc.clientOff, Tracer: newTracer(&fromServer)}))
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
				off  bool
			}{{"client", &fromClient, tc.clientOff}, {"server", &fromServer, tc.serverOff}} {
				counts := countECN(side.rcvd)
				ect0, notECT := counts[qlog.ECT0], counts[qlog.ECTNot]
				t.Logf("Packets from the %s: %d ECT(0), %d Not-ECT", side.name, ect0, notECT)
				if side.off {
					require.Zero(t, ect0, "the %s sent ECT(0) packets", side.name)
					require.NotZero(t, notECT, "the %s sent no Not-ECT packets", side.name)
				} else {
					require.NotZero(t, ect0, "the %s sent no ECT(0) packets", side.name)
				}
			}
		})
	}
}
