//go:build linux

package self_test

import (
	"context"
	"io"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
)

// ecnCounter counts the ECN codepoints of the 1-RTT packets that a connection receives.
// The quic-go socket reads the TOS byte of each packet with IP_RECVTOS.
type ecnCounter struct {
	mu     sync.Mutex
	counts map[logging.ECN]int
}

func (c *ecnCounter) tracer(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
	return &logging.ConnectionTracer{
		ReceivedShortHeaderPacket: func(_ *logging.ShortHeader, _ logging.ByteCount, ecn logging.ECN, _ []logging.Frame) {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.counts[ecn]++
		},
	}
}

func (c *ecnCounter) get(ecn logging.ECN) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[ecn]
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
			fromClient := &ecnCounter{counts: map[logging.ECN]int{}}
			fromServer := &ecnCounter{counts: map[logging.ECN]int{}}
			ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(),
				getQuicConfig(&quic.Config{DisableECN: tc.serverOff, Tracer: fromClient.tracer}))
			require.NoError(t, err)
			defer ln.Close()

			ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(5*time.Second))
			defer cancel()
			conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(),
				getQuicConfig(&quic.Config{DisableECN: tc.clientOff, Tracer: fromServer.tracer}))
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
				rcvd *ecnCounter
				off  bool
			}{{"client", fromClient, tc.clientOff}, {"server", fromServer, tc.serverOff}} {
				ect0, notECT := side.rcvd.get(logging.ECT0), side.rcvd.get(logging.ECTNot)
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
